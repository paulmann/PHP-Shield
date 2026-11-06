<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;

/**
 * AbuseIPDB v2 `/check` client.
 *
 * The same class serves both communities because they share the contract
 * (see the API-V2-CONTRACT note in the abuseipdb.ru project): identical paths,
 * identical `Key:` header, identical envelopes. Only the base URL differs.
 */
final class AbuseIpDbProvider implements ReputationProviderInterface
{
    public const COM_BASE_URL = 'https://api.abuseipdb.com/api/v2';

    public const RU_BASE_URL = 'https://abuseipdb.ru/api/v2';

    public function __construct(
        private readonly HttpTransportInterface $transport,
        private readonly string $apiKey,
        private readonly string $baseUrl = self::COM_BASE_URL,
        private readonly string $providerName = 'abuseipdb.com',
        private readonly int $maxAgeDays = 90,
        private readonly float $timeout = 2.0
    ) {
    }

    public static function com(
        HttpTransportInterface $transport,
        string $apiKey,
        int $maxAgeDays = 90,
        float $timeout = 2.0
    ): self {
        return new self($transport, $apiKey, self::COM_BASE_URL, 'abuseipdb.com', $maxAgeDays, $timeout);
    }

    public static function ru(
        HttpTransportInterface $transport,
        string $apiKey,
        int $maxAgeDays = 90,
        float $timeout = 2.0
    ): self {
        return new self($transport, $apiKey, self::RU_BASE_URL, 'abuseipdb.ru', $maxAgeDays, $timeout);
    }

    public function name(): string
    {
        return $this->providerName;
    }

    public function lookup(string $ip): ?IpReputation
    {
        if ($this->apiKey === '') {
            throw ThreatIntelException::authenticationFailed($this->providerName);
        }

        if (!$this->isQueryable($ip)) {
            return null;
        }

        $response = $this->transport->get(
            $this->buildUrl($ip),
            ['Key' => $this->apiKey, 'Accept' => 'application/json'],
            $this->timeout
        );

        return match (true) {
            $response['status'] === 200 => $this->parse($response['body']),
            in_array($response['status'], [401, 403], true) => throw ThreatIntelException::authenticationFailed(
                $this->providerName
            ),
            $response['status'] === 422 => null,
            $response['status'] === 429 => throw ThreatIntelException::rateLimited(
                $this->providerName,
                $this->retryAfter($response['headers'])
            ),
            default => throw ThreatIntelException::unavailable(
                $this->providerName,
                'HTTP ' . $response['status']
            ),
        };
    }

    private function buildUrl(string $ip): string
    {
        $maxAgeDays = max(1, min(365, $this->maxAgeDays));

        return rtrim($this->baseUrl, '/')
            . '/check?ipAddress=' . rawurlencode($ip)
            . '&maxAgeInDays=' . $maxAgeDays;
    }

    private function isQueryable(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // Private, reserved and loopback addresses carry no public reputation.
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    private function parse(string $body): ?IpReputation
    {
        $decoded = json_decode($body, true);

        if (!is_array($decoded)) {
            throw ThreatIntelException::unavailable($this->providerName, 'response is not valid JSON');
        }

        $data = $decoded['data'] ?? null;

        if (!is_array($data)) {
            return null;
        }

        return IpReputation::fromApiData($data, $this->providerName, time());
    }

    /**
     * @param array<string, string> $headers
     */
    private function retryAfter(array $headers): int
    {
        $retryAfter = $headers['retry-after'] ?? null;

        if (is_string($retryAfter) && preg_match('/^\d+$/', $retryAfter) === 1) {
            return (int) $retryAfter;
        }

        if (is_string($retryAfter) && $retryAfter !== '') {
            $timestamp = strtotime($retryAfter);

            if ($timestamp !== false) {
                return max(0, $timestamp - time());
            }
        }

        $reset = $headers['x-ratelimit-reset'] ?? null;

        if (is_string($reset) && preg_match('/^\d+$/', $reset) === 1) {
            return max(0, (int) $reset - time());
        }

        return 60;
    }
}
