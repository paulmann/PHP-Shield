<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\Support;

use Deynekin\PhpShield\RateLimiting\RateLimiterInterface;

/**
 * Controllable rate limiter for tests.
 */
final class FakeRateLimiter implements RateLimiterInterface
{
    public int $calls = 0;

    public function __construct(public bool $allow = true)
    {
    }

    public function allow(string $key, int $limit, int $windowSeconds): bool
    {
        $this->calls++;

        return $this->allow;
    }

    public function getRemaining(string $key, int $limit, int $windowSeconds): int
    {
        return $this->allow ? $limit : 0;
    }
}
