<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * Normalised IP reputation reading.
 *
 * The field names follow the AbuseIPDB v2 `check` payload so the same object
 * can be produced by abuseipdb.com and by abuseipdb.ru, which implements the
 * same contract.
 */
final class IpReputation
{
    public function __construct(
        public readonly string $ip,
        public readonly string $provider,
        public readonly int $abuseConfidenceScore,
        public readonly bool $isWhitelisted,
        public readonly int $totalReports,
        public readonly int $distinctUsers,
        public readonly string $countryCode,
        public readonly string $isp,
        public readonly string $usageType,
        public readonly string $lastReportedAt,
        public readonly int $fetchedAt
    ) {
    }

    /**
     * @param array<string, mixed> $data the `data` object of the API response
     */
    public static function fromApiData(array $data, string $provider, int $fetchedAt): self
    {
        return new self(
            ip: self::stringValue($data, 'ipAddress'),
            provider: $provider,
            abuseConfidenceScore: max(0, min(100, self::intValue($data, 'abuseConfidenceScore'))),
            isWhitelisted: self::boolValue($data, 'isWhitelisted'),
            totalReports: self::intValue($data, 'totalReports'),
            distinctUsers: self::intValue($data, 'numDistinctUsers'),
            countryCode: self::stringValue($data, 'countryCode'),
            isp: self::stringValue($data, 'isp'),
            usageType: self::stringValue($data, 'usageType'),
            lastReportedAt: self::stringValue($data, 'lastReportedAt'),
            fetchedAt: $fetchedAt
        );
    }

    /**
     * Rebuild from a cached array (see toArray()).
     *
     * @param array<string, mixed> $row
     */
    public static function fromArray(array $row): ?self
    {
        $ip = $row['ip'] ?? null;
        $provider = $row['provider'] ?? null;
        $fetchedAt = $row['fetched_at'] ?? null;

        if (!is_string($ip) || $ip === '' || !is_string($provider) || !is_int($fetchedAt)) {
            return null;
        }

        return new self(
            ip: $ip,
            provider: $provider,
            abuseConfidenceScore: is_int($row['score'] ?? null) ? $row['score'] : 0,
            isWhitelisted: ($row['is_whitelisted'] ?? false) === true,
            totalReports: is_int($row['total_reports'] ?? null) ? $row['total_reports'] : 0,
            distinctUsers: is_int($row['distinct_users'] ?? null) ? $row['distinct_users'] : 0,
            countryCode: is_string($row['country_code'] ?? null) ? $row['country_code'] : '',
            isp: is_string($row['isp'] ?? null) ? $row['isp'] : '',
            usageType: is_string($row['usage_type'] ?? null) ? $row['usage_type'] : '',
            lastReportedAt: is_string($row['last_reported_at'] ?? null) ? $row['last_reported_at'] : '',
            fetchedAt: $fetchedAt
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'provider' => $this->provider,
            'score' => $this->abuseConfidenceScore,
            'is_whitelisted' => $this->isWhitelisted,
            'total_reports' => $this->totalReports,
            'distinct_users' => $this->distinctUsers,
            'country_code' => $this->countryCode,
            'isp' => $this->isp,
            'usage_type' => $this->usageType,
            'last_reported_at' => $this->lastReportedAt,
            'fetched_at' => $this->fetchedAt,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function stringValue(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function intValue(array $data, string $key): int
    {
        $value = $data[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function boolValue(array $data, string $key): bool
    {
        $value = $data[$key] ?? null;

        return $value === true || $value === 1 || $value === 'true';
    }
}
