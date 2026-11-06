<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\RateLimiting;

use Redis;
use RedisException;

/**
 * Production-grade rate limiter using Redis.
 * Atomic INCR + EXPIRE. Recommended for high-traffic applications.
 */
class RedisRateLimiter implements RateLimiterInterface
{
    public function __construct(
        private readonly Redis $redis,
        private readonly string $prefix = 'phpshield:rl:'
    ) {
    }

    public function allow(string $key, int $limit, int $windowSeconds): bool
    {
        $fullKey = $this->prefix . $key;
        $windowSeconds = max(1, $windowSeconds);

        try {
            $current = $this->redis->incr($fullKey);

            if (!is_int($current)) {
                error_log('PHP-Shield RedisRateLimiter: INCR returned a non-integer result.');

                return true;
            }

            if ($current === 1) {
                $this->redis->expire($fullKey, $windowSeconds);
            } elseif ($this->redis->ttl($fullKey) === -1) {
                // Safety: the key exists without a TTL, so it would never expire.
                $this->redis->expire($fullKey, $windowSeconds);
            }

            return $current <= $limit;
        } catch (RedisException $exception) {
            // Fail open: a Redis outage must not block every visitor.
            error_log('PHP-Shield RedisRateLimiter error: ' . $exception->getMessage());

            return true;
        }
    }

    public function getRemaining(string $key, int $limit, int $windowSeconds): int
    {
        $fullKey = $this->prefix . $key;

        try {
            $current = $this->redis->get($fullKey);

            if (is_int($current)) {
                return max(0, $limit - $current);
            }

            if (is_string($current) && is_numeric($current)) {
                return max(0, $limit - (int) $current);
            }

            return $limit;
        } catch (RedisException $exception) {
            return $limit;
        }
    }

    public function reset(string $key): void
    {
        $this->redis->del($this->prefix . $key);
    }
}
