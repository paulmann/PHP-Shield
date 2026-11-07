<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Queue of addresses waiting for a reputation lookup.
 *
 * The request path only writes to it (a single INSERT), the worker drains it
 * out of band. Rows are deduplicated by address and retried with backoff.
 */
interface ReputationQueueInterface
{
    /**
     * Ask for one address to be looked up later. Repeated calls for the same
     * address must not create duplicates.
     */
    public function push(string $ip): void;

    /**
     * Addresses that are due now, oldest first.
     *
     * @return list<string>
     */
    public function claim(int $limit): array;

    /**
     * Remove an address from the queue: it was looked up (or had no opinion).
     */
    public function complete(string $ip): void;

    /**
     * Keep the address for a later attempt.
     */
    public function fail(string $ip, string $error, int $retryAfterSeconds = 300): void;

    /**
     * Number of addresses waiting.
     */
    public function size(): int;
}
