<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Storage;

/**
 * MySQL/MariaDB block store: blocks, incident journal, failed-attempt counters.
 *
 * Tables are created on first use unless auto-migration is disabled; in
 * production apply migrations/schema.sql and pass autoMigrate = false so the
 * request path never issues DDL.
 *
 * Every database failure is logged and reported as "nothing is blocked". That
 * is a deliberate fail-open trade-off for a shared-hosting library: a database
 * hiccup must not take the site down. See docs/adr.md (ADR-006).
 */
class MysqlBlockStore implements BlockStoreInterface, FailedAttemptStoreInterface, MaintenanceStoreInterface
{
    private const BLOCK_TYPES = ['temporary', 'permanent'];

    private const SEVERITIES = ['low', 'medium', 'high', 'critical'];

    private const MAX_DESCRIPTION_LENGTH = 4000;

    private const MAX_INCIDENT_TYPE_LENGTH = 64;

    public function __construct(
        private readonly \mysqli $db,
        private readonly bool $autoMigrate = true
    ) {
        if ($this->autoMigrate) {
            $this->ensureTables();
        }
    }

    public function isBlocked(string $ip): bool
    {
        return $this->hasBlock(
            'SELECT 1 FROM php_shield_ip_blocks
             WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW())
             LIMIT 1',
            [$ip]
        );
    }

    public function isPermanentlyBlocked(string $ip): bool
    {
        return $this->hasBlock(
            "SELECT 1 FROM php_shield_ip_blocks
             WHERE ip_address = ? AND block_type = 'permanent'
               AND (expires_at IS NULL OR expires_at > NOW())
             LIMIT 1",
            [$ip]
        );
    }

    public function block(
        string $ip,
        string $reason,
        ?int $durationSeconds = null,
        string $type = 'temporary',
        string $severity = 'medium'
    ): void {
        if (!in_array($type, self::BLOCK_TYPES, true)) {
            $type = 'temporary';
        }

        $severity = in_array($severity, self::SEVERITIES, true) ? $severity : 'medium';
        $reason = mb_substr($reason, 0, 255);

        // Expiry is computed by MySQL, never by PHP: the two clocks may sit in
        // different time zones and a PHP-side date would then be compared
        // against NOW() and expire immediately.
        if ($durationSeconds === null || $durationSeconds <= 0) {
            $stmt = $this->statement(
                'INSERT INTO php_shield_ip_blocks (ip_address, block_type, severity, reason, expires_at, created_at)
                 VALUES (?, ?, ?, ?, NULL, NOW())
                 ON DUPLICATE KEY UPDATE
                     block_type = VALUES(block_type),
                     severity = VALUES(severity),
                     reason = VALUES(reason),
                     expires_at = NULL,
                     updated_at = NOW()',
                'ssss',
                [$ip, $type, $severity, $reason]
            );

            $stmt?->close();

            return;
        }

        $stmt = $this->statement(
            'INSERT INTO php_shield_ip_blocks (ip_address, block_type, severity, reason, expires_at, created_at)
             VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), NOW())
             ON DUPLICATE KEY UPDATE
                 block_type = VALUES(block_type),
                 severity = VALUES(severity),
                 reason = VALUES(reason),
                 expires_at = VALUES(expires_at),
                 updated_at = NOW()',
            'ssssi',
            [$ip, $type, $severity, $reason, $durationSeconds]
        );

        $stmt?->close();
    }

    public function unblock(string $ip): void
    {
        $stmt = $this->statement('DELETE FROM php_shield_ip_blocks WHERE ip_address = ?', 's', [$ip]);

        $stmt?->close();
    }

    public function getActiveBlocks(int $limit = 100): array
    {
        $limit = max(1, min(1000, $limit));

        try {
            $result = $this->db->query(
                'SELECT ip_address, block_type, severity, reason, expires_at, created_at
                 FROM php_shield_ip_blocks
                 WHERE expires_at IS NULL OR expires_at > NOW()
                 ORDER BY created_at DESC
                 LIMIT ' . $limit
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return [];
        }

        if (!$result instanceof \mysqli_result) {
            return [];
        }

        /** @var list<array<string, mixed>> $rows */
        $rows = $result->fetch_all(MYSQLI_ASSOC);

        return $rows;
    }

    public function logIncident(
        string $ip,
        ?int $userId,
        string $type,
        string $description,
        string $severity,
        array $context = []
    ): void {
        if (!in_array($severity, self::SEVERITIES, true)) {
            $severity = 'medium';
        }

        $contextJson = null;

        if ($context !== []) {
            // Never throw here: an invalid UTF-8 byte in a scanned payload must
            // not turn threat logging into a fatal error.
            $encoded = json_encode(
                $context,
                JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR
            );
            $contextJson = is_string($encoded) ? $encoded : null;
        }

        $stmt = $this->statement(
            'INSERT INTO php_shield_incidents
                (ip_address, user_id, incident_type, description, severity, context, occurred_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())',
            'sissss',
            [
                $ip,
                $userId,
                mb_substr($type, 0, self::MAX_INCIDENT_TYPE_LENGTH),
                mb_substr($description, 0, self::MAX_DESCRIPTION_LENGTH),
                $severity,
                $contextJson,
            ]
        );

        $stmt?->close();
    }

    public function countIncidents(string $ip, int $windowSeconds): int
    {
        $since = time() - max(1, $windowSeconds);

        try {
            $stmt = $this->db->prepare(
                'SELECT COUNT(*) AS c FROM php_shield_incidents
                 WHERE ip_address = ? AND occurred_at >= FROM_UNIXTIME(?)'
            );

            if ($stmt === false) {
                return 0;
            }

            $stmt->bind_param('si', $ip, $since);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result instanceof \mysqli_result ? $result->fetch_assoc() : null;
            $stmt->close();

            return is_array($row) && isset($row['c']) && is_numeric($row['c']) ? (int) $row['c'] : 0;
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return 0;
        }
    }

    public function getRecentIncidents(int $limit = 50): array
    {
        $limit = max(1, min(500, $limit));

        try {
            $result = $this->db->query(
                'SELECT id, ip_address, user_id, incident_type, description, severity, context, occurred_at
                 FROM php_shield_incidents
                 ORDER BY id DESC
                 LIMIT ' . $limit
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return [];
        }

        if (!$result instanceof \mysqli_result) {
            return [];
        }

        /** @var list<array<string, mixed>> $rows */
        $rows = $result->fetch_all(MYSQLI_ASSOC);

        return $rows;
    }

    public function recordFailedAttempt(string $ip): int
    {
        $stmt = $this->statement(
            'INSERT INTO php_shield_failed_attempts (ip_address, attempts, last_attempt_at)
             VALUES (?, 1, NOW())
             ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt_at = NOW()',
            's',
            [$ip]
        );

        $stmt?->close();

        return $this->getFailedAttempts($ip);
    }

    public function getFailedAttempts(string $ip): int
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT attempts FROM php_shield_failed_attempts WHERE ip_address = ? LIMIT 1'
            );

            if ($stmt === false) {
                return 0;
            }

            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result instanceof \mysqli_result ? $result->fetch_assoc() : null;
            $stmt->close();

            return is_array($row) && isset($row['attempts']) && is_numeric($row['attempts']) ? (int) $row['attempts'] : 0;
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return 0;
        }
    }

    public function clearFailedAttempts(string $ip): void
    {
        $stmt = $this->statement('DELETE FROM php_shield_failed_attempts WHERE ip_address = ?', 's', [$ip]);

        $stmt?->close();
    }

    public function cleanup(int $retentionDays = 30): array
    {
        return [
            'blocks' => $this->delete(
                "DELETE FROM php_shield_ip_blocks
                 WHERE block_type = 'temporary' AND expires_at IS NOT NULL AND expires_at < NOW()"
            ),
            'incidents' => $this->delete(
                'DELETE FROM php_shield_incidents WHERE occurred_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
                max(1, $retentionDays)
            ),
            'attempts' => $this->delete(
                'DELETE FROM php_shield_failed_attempts WHERE last_attempt_at < DATE_SUB(NOW(), INTERVAL 1 DAY)'
            ),
        ];
    }

    public function getStats(): array
    {
        $stats = [
            'active_blocks' => 0,
            'permanent_blocks' => 0,
            'incidents_24h' => 0,
            'incidents_total' => 0,
            'high_severity_7d' => 0,
            'by_type' => [],
            'top_ips' => [],
        ];

        $counters = [
            'active_blocks' => 'SELECT COUNT(*) AS c FROM php_shield_ip_blocks WHERE expires_at IS NULL OR expires_at > NOW()',
            'permanent_blocks' => "SELECT COUNT(*) AS c FROM php_shield_ip_blocks WHERE block_type = 'permanent' AND (expires_at IS NULL OR expires_at > NOW())",
            'incidents_24h' => 'SELECT COUNT(*) AS c FROM php_shield_incidents WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)',
            'incidents_total' => 'SELECT COUNT(*) AS c FROM php_shield_incidents',
            'high_severity_7d' => "SELECT COUNT(*) AS c FROM php_shield_incidents WHERE severity IN ('high','critical') AND occurred_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
        ];

        foreach ($counters as $key => $sql) {
            $value = $this->scalar($sql);

            if ($value !== null) {
                $stats[$key] = $value;
            }
        }

        $stats['by_type'] = $this->rows(
            'SELECT incident_type, COUNT(*) AS hits FROM php_shield_incidents
             GROUP BY incident_type ORDER BY hits DESC LIMIT 20'
        );
        $stats['top_ips'] = $this->rows(
            'SELECT ip_address, COUNT(*) AS hits FROM php_shield_incidents
             GROUP BY ip_address ORDER BY hits DESC LIMIT 10'
        );

        return $stats;
    }

    /**
     * @param list<mixed> $params
     */
    private function hasBlock(string $sql, array $params): bool
    {
        $stmt = $this->statement($sql, 's', $params);

        if (!$stmt instanceof \mysqli_stmt) {
            return false;
        }

        $result = $stmt->get_result();
        $blocked = $result instanceof \mysqli_result && $result->num_rows > 0;
        $stmt->close();

        return $blocked;
    }

    /**
     * @param list<mixed> $params
     */
    private function statement(string $sql, string $types, array $params): ?\mysqli_stmt
    {
        try {
            $stmt = $this->db->prepare($sql);

            if ($stmt === false) {
                return null;
            }

            if ($params !== []) {
                $stmt->bind_param($types, ...$params);
            }

            if (!$stmt->execute()) {
                $stmt->close();

                return null;
            }

            return $stmt;
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return null;
        }
    }

    private function delete(string $sql, ?int $days = null): int
    {
        try {
            if ($days === null) {
                $result = $this->db->query($sql);

                return $result === false ? 0 : max(0, (int) $this->db->affected_rows);
            }

            $stmt = $this->db->prepare($sql);

            if ($stmt === false) {
                return 0;
            }

            $stmt->bind_param('i', $days);
            $stmt->execute();
            $deleted = (int) $stmt->affected_rows;
            $stmt->close();

            return $deleted;
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return 0;
        }
    }

    private function scalar(string $sql): ?int
    {
        try {
            $result = $this->db->query($sql);
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return null;
        }

        if (!$result instanceof \mysqli_result) {
            return null;
        }

        $row = $result->fetch_assoc();

        return is_array($row) && isset($row['c']) && is_numeric($row['c']) ? (int) $row['c'] : null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rows(string $sql): array
    {
        try {
            $result = $this->db->query($sql);
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());

            return [];
        }

        if (!$result instanceof \mysqli_result) {
            return [];
        }

        /** @var list<array<string, mixed>> $rows */
        $rows = $result->fetch_all(MYSQLI_ASSOC);

        return $rows;
    }

    private function ensureTables(): void
    {
        $statements = [
            "CREATE TABLE IF NOT EXISTS php_shield_ip_blocks (
                ip_address VARCHAR(45) NOT NULL PRIMARY KEY,
                block_type ENUM('temporary', 'permanent') NOT NULL DEFAULT 'temporary',
                severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
                reason VARCHAR(255) NULL,
                expires_at DATETIME NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NULL,
                KEY idx_expires (expires_at),
                KEY idx_block_type (block_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            "CREATE TABLE IF NOT EXISTS php_shield_incidents (
                id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                ip_address VARCHAR(45) NOT NULL,
                user_id INT UNSIGNED NULL,
                incident_type VARCHAR(64) NOT NULL,
                description TEXT NULL,
                severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
                context JSON NULL,
                occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_ip_time (ip_address, occurred_at),
                KEY idx_type_severity (incident_type, severity),
                KEY idx_occurred (occurred_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            "CREATE TABLE IF NOT EXISTS php_shield_failed_attempts (
                ip_address VARCHAR(45) NOT NULL PRIMARY KEY,
                attempts INT UNSIGNED NOT NULL DEFAULT 0,
                last_attempt_at DATETIME NOT NULL,
                KEY idx_last_attempt (last_attempt_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        ];

        foreach ($statements as $sql) {
            try {
                $this->db->query($sql);
            } catch (\mysqli_sql_exception $exception) {
                // Missing DDL privileges are not fatal if the tables already exist.
                error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());
            }
        }

        $this->ensureBlockSeverityColumn();
    }

    /**
     * Upgrade a blocks table created by 1.x, which had no severity column.
     */
    private function ensureBlockSeverityColumn(): void
    {
        try {
            $result = $this->db->query("SHOW COLUMNS FROM php_shield_ip_blocks LIKE 'severity'");

            if ($result instanceof \mysqli_result && $result->num_rows > 0) {
                return;
            }

            $this->db->query(
                "ALTER TABLE php_shield_ip_blocks
                 ADD COLUMN severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium'
                 AFTER block_type"
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlBlockStore: ' . $exception->getMessage());
        }
    }
}
