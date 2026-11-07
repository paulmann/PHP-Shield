<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Shared queue on the same MySQL connection the rest of the state uses.
 *
 * Enqueue is one INSERT ... ON DUPLICATE KEY UPDATE and therefore cheap enough
 * for the request path; the lookup itself happens in the worker.
 */
final class MysqlReputationQueue implements ReputationQueueInterface
{
    private const MAX_ERROR_LENGTH = 255;

    public function __construct(
        private readonly \mysqli $db,
        private readonly bool $autoMigrate = true
    ) {
        if ($this->autoMigrate) {
            $this->ensureTable();
        }
    }

    public function push(string $ip): void
    {
        if ($ip === '') {
            return;
        }

        try {
            $stmt = $this->db->prepare(
                'INSERT INTO php_shield_reputation_queue (ip_address, requested_at, attempts, next_attempt_at)
                 VALUES (?, NOW(), 0, NOW())
                 ON DUPLICATE KEY UPDATE ip_address = ip_address'
            );

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $stmt->close();
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());
        }
    }

    public function claim(int $limit): array
    {
        $limit = max(1, min(500, $limit));

        try {
            $result = $this->db->query(
                'SELECT ip_address FROM php_shield_reputation_queue
                 WHERE next_attempt_at <= NOW()
                 ORDER BY next_attempt_at ASC
                 LIMIT ' . $limit
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());

            return [];
        }

        if (!$result instanceof \mysqli_result) {
            return [];
        }

        $ips = [];

        while (is_array($row = $result->fetch_assoc())) {
            $ip = $row['ip_address'] ?? null;

            if (is_string($ip) && $ip !== '') {
                $ips[] = $ip;
            }
        }

        return $ips;
    }

    public function complete(string $ip): void
    {
        try {
            $stmt = $this->db->prepare('DELETE FROM php_shield_reputation_queue WHERE ip_address = ?');

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $stmt->close();
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());
        }
    }

    public function fail(string $ip, string $error, int $retryAfterSeconds = 300): void
    {
        $message = mb_substr($error, 0, self::MAX_ERROR_LENGTH);

        try {
            $stmt = $this->db->prepare(
                'UPDATE php_shield_reputation_queue
                 SET attempts = attempts + 1,
                     last_error = ?,
                     next_attempt_at = DATE_ADD(NOW(), INTERVAL ? SECOND)
                 WHERE ip_address = ?'
            );

            if ($stmt === false) {
                return;
            }

            $retryAfter = max(1, $retryAfterSeconds);
            $stmt->bind_param('sis', $message, $retryAfter, $ip);
            $stmt->execute();
            $stmt->close();
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());
        }
    }

    public function size(): int
    {
        try {
            $result = $this->db->query('SELECT COUNT(*) AS c FROM php_shield_reputation_queue');
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());

            return 0;
        }

        if (!$result instanceof \mysqli_result) {
            return 0;
        }

        $row = $result->fetch_assoc();

        return is_array($row) && isset($row['c']) && is_numeric($row['c']) ? (int) $row['c'] : 0;
    }

    private function ensureTable(): void
    {
        try {
            $this->db->query(
                'CREATE TABLE IF NOT EXISTS php_shield_reputation_queue (
                    ip_address VARCHAR(45) NOT NULL PRIMARY KEY,
                    requested_at DATETIME NOT NULL,
                    attempts INT UNSIGNED NOT NULL DEFAULT 0,
                    last_error VARCHAR(255) NULL,
                    next_attempt_at DATETIME NOT NULL,
                    KEY idx_next_attempt (next_attempt_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationQueue: ' . $exception->getMessage());
        }
    }
}
