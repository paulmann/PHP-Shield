<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\RateLimiting;

/**
 * Counter table rate limiter.
 *
 * Suitable for low and medium traffic. The check and the insert are two
 * statements, so a burst of concurrent requests can overshoot the limit by the
 * number of in-flight requests. Use RedisRateLimiter when that matters.
 *
 * Rows are never removed automatically: schedule prune() (or the SQL in
 * migrations/schema.sql) so the table does not grow without bound.
 */
class DatabaseRateLimiter implements RateLimiterInterface
{
    public function __construct(
        private readonly \mysqli $db,
        private readonly bool $autoMigrate = true
    ) {
        if ($this->autoMigrate) {
            $this->ensureTable();
        }
    }

    public function allow(string $key, int $limit, int $windowSeconds): bool
    {
        $limit = max(1, $limit);
        $windowSeconds = max(1, $windowSeconds);

        $hits = $this->countHits($key, $windowSeconds);

        if ($hits === null) {
            // Fail open: a database problem must not block every visitor.
            return true;
        }

        if ($hits >= $limit) {
            return false;
        }

        $this->recordHit($key);

        return true;
    }

    public function getRemaining(string $key, int $limit, int $windowSeconds): int
    {
        $hits = $this->countHits($key, max(1, $windowSeconds));

        return max(0, $limit - ($hits ?? 0));
    }

    /**
     * Delete rows older than the given age.
     *
     * @return int number of deleted rows, 0 when the statement failed
     */
    public function prune(int $olderThanSeconds = 172800): int
    {
        $cutoff = time() - max(60, $olderThanSeconds);

        try {
            $stmt = $this->db->prepare('DELETE FROM php_shield_rate_limit WHERE created_at < FROM_UNIXTIME(?)');

            if ($stmt === false) {
                return 0;
            }

            $stmt->bind_param('i', $cutoff);
            $stmt->execute();
            $deleted = (int) $stmt->affected_rows;
            $stmt->close();

            return max(0, $deleted);
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield DatabaseRateLimiter: ' . $exception->getMessage());

            return 0;
        }
    }

    private function countHits(string $key, int $windowSeconds): ?int
    {
        $windowStart = time() - $windowSeconds;

        try {
            $stmt = $this->db->prepare(
                'SELECT COUNT(*) AS cnt FROM php_shield_rate_limit
                 WHERE rate_key = ? AND created_at >= FROM_UNIXTIME(?)'
            );

            if ($stmt === false) {
                return null;
            }

            $stmt->bind_param('si', $key, $windowStart);
            $stmt->execute();
            $result = $stmt->get_result();

            if (!$result instanceof \mysqli_result) {
                $stmt->close();

                return null;
            }

            $row = $result->fetch_assoc();
            $stmt->close();

            return is_array($row) && isset($row['cnt']) && is_numeric($row['cnt']) ? (int) $row['cnt'] : 0;
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield DatabaseRateLimiter: ' . $exception->getMessage());

            return null;
        }
    }

    private function recordHit(string $key): void
    {
        try {
            $stmt = $this->db->prepare('INSERT INTO php_shield_rate_limit (rate_key, created_at) VALUES (?, NOW())');

            if ($stmt === false) {
                return;
            }

            $stmt->bind_param('s', $key);
            $stmt->execute();
            $stmt->close();
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield DatabaseRateLimiter: ' . $exception->getMessage());
        }
    }

    private function ensureTable(): void
    {
        try {
            $this->db->query(
                'CREATE TABLE IF NOT EXISTS php_shield_rate_limit (
                    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
                    rate_key VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL,
                    KEY idx_key_time (rate_key, created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            );
        } catch (\mysqli_sql_exception $exception) {
            error_log('PHP-Shield DatabaseRateLimiter: ' . $exception->getMessage());
        }
    }
}
