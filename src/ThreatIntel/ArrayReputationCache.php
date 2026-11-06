<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * In-process cache: one request, no shared state.
 *
 * Suitable for single-request tools and tests; in a web process every request
 * starts empty, so use MysqlReputationCache (or your own) to share readings.
 */
final class ArrayReputationCache implements ReputationCacheInterface
{
    /**
     * @var array<string, array{value: mixed, expiresAt: int}>
     */
    private array $entries = [];

    public function get(string $key): mixed
    {
        $entry = $this->entries[$key] ?? null;

        if ($entry === null) {
            return null;
        }

        if ($entry['expiresAt'] <= time()) {
            unset($this->entries[$key]);

            return null;
        }

        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->entries[$key] = [
            'value' => $value,
            'expiresAt' => time() + max(1, $ttlSeconds),
        ];
    }
}
