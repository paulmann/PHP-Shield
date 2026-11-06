<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Storage;

/**
 * Optional capability: counters for failed logins / failed API calls.
 *
 * Implemented by MysqlBlockStore. The middleware feature-detects it, so a
 * custom block store that does not track attempts keeps working unchanged.
 */
interface FailedAttemptStoreInterface
{
    /**
     * Record one failure and return the current counter value.
     */
    public function recordFailedAttempt(string $ip): int;

    public function getFailedAttempts(string $ip): int;

    public function clearFailedAttempts(string $ip): void;
}
