<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Shared reputation cache on top of the same MySQL connection the block store uses.
 */
final class MysqlReputationCache implements ReputationCacheInterface
{
    public function __construct(
        private readonly \mysqli $db,
        private readonly bool $autoMigrate = true
    ) {
        if ($this->autoMigrate) {
            $this->ensureTable();
        }
    }

    public function get(string $key): mixed
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT payload FROM php_shield_ip_reputation WHERE cache_key = ? AND expires_at > NOW() LIMIT 1'
            );

            if ($stmt === false) {
                return null;
            }

            $stmt->bind_param('s', $key);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result instanceof \mysqli_result ? $result->fetch_assoc() : null;
            $stmt->close();

            if (!is_array($row) || !isset($row['payload']) || !is_string($row['payload'])) {
                return null;
            }

            return json_decode($row['payload'], true);
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationCache: ' . $exception->getMessage());

            return null;
        }
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $payload = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        if (!is_string($payload)) {
            return;
        }

        try {
            $stmt = $this->db->prepare(
                'INSERT INTO php_shield_ip_reputation (cache_key, payload, expires_at, created_at)
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), NOW())
                 ON DUPLICATE KEY UPDATE
                     payload = VALUES(payload),
                     expires_at = VALUES(expires_at),
                     created_at = NOW()'
            );

            if ($stmt === false) {
                return;
            }

            $ttl = max(1, $ttlSeconds);
            $stmt->bind_param('ssi', $key, $payload, $ttl);
            $stmt->execute();
            $stmt->close();
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationCache: ' . $exception->getMessage());
        }
    }

    private function ensureTable(): void
    {
        try {
            $this->db->query(
                'CREATE TABLE IF NOT EXISTS php_shield_ip_reputation (
                    cache_key VARCHAR(190) NOT NULL PRIMARY KEY,
                    payload JSON NOT NULL,
                    expires_at DATETIME NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_expires (expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield MysqlReputationCache: ' . $exception->getMessage());
        }
    }
}
