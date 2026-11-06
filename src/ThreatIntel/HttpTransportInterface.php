<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Minimal HTTP GET abstraction so the providers can be tested without network.
 */
interface HttpTransportInterface
{
    /**
     * @param array<string, string> $headers
     * @return array{status: int, body: string, headers: array<string, string>}
     * @throws \Deynekin\PhpShield\Exception\ThreatIntelException on transport failure
     */
    public function get(string $url, array $headers, float $timeout): array;
}
