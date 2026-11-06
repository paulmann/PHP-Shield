<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\RateLimiting;

interface RateLimiterInterface
{
    /**
     * Check if the request is allowed. Returns true if under limit.
     * Should be atomic where possible.
     */
    public function allow(string $key, int $limit, int $windowSeconds): bool;

    public function getRemaining(string $key, int $limit, int $windowSeconds): int;
}
