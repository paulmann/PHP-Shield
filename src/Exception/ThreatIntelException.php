<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Exception;

/**
 * Raised when a reputation provider cannot answer.
 *
 * The middleware treats it as "no data" (fail open) unless configured
 * otherwise, so an API outage never blocks honest visitors.
 */
class ThreatIntelException extends ShieldException
{
    private int $retryAfter = 0;

    public static function authenticationFailed(string $provider): self
    {
        return new self("{$provider}: authentication failed (check the API key).");
    }

    public static function rateLimited(string $provider, int $retryAfter): self
    {
        $exception = new self("{$provider}: rate limit reached, retry after {$retryAfter} second(s).");
        $exception->retryAfter = max(0, $retryAfter);

        return $exception;
    }

    public static function unavailable(string $provider, string $reason): self
    {
        return new self("{$provider}: {$reason}");
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
