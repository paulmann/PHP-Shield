<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;

/**
 * One source of IP reputation (abuseipdb.com, abuseipdb.ru, ...).
 */
interface ReputationProviderInterface
{
    public function name(): string;

    /**
     * Ask the provider about one address.
     *
     * Returns null when the provider has no opinion (private address, invalid
     * input, empty result) and throws when it could not answer at all.
     *
     * @throws ThreatIntelException
     */
    public function lookup(string $ip): ?IpReputation;
}
