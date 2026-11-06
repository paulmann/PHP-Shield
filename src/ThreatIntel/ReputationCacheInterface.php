<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Small cache contract for reputation readings and circuit-breaker state.
 */
interface ReputationCacheInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttlSeconds): void;
}
