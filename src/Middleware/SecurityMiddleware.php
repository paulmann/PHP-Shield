<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Middleware;

use Deynekin\PhpShield\Ip\CidrMatcher;
use Deynekin\PhpShield\Storage\BlockStoreInterface;
use Deynekin\PhpShield\Storage\FailedAttemptStoreInterface;
use Deynekin\PhpShield\Storage\MaintenanceStoreInterface;
use Deynekin\PhpShield\Support\Config;

/**
 * Security state and block policy — the state half of PHP Shield.
 *
 * The split of responsibilities is what matters:
 *
 *   - this class owns state: blocks, the incident journal, failed-attempt
 *     counters, retention cleanup and statistics;
 *   - it does NOT detect anything. Scanning lives in Shield, which calls
 *     recordIncident()/blockIp() with its verdict.
 *
 * One source of truth for detection, one for state. Block lifetime grows with
 * severity (see severity_block_multipliers) and a permanent block is always an
 * explicit operator decision, never an automatic one.
 */
class SecurityMiddleware
{
    public const SEVERITY_LOW = 'low';

    public const SEVERITY_MEDIUM = 'medium';

    public const SEVERITY_HIGH = 'high';

    public const SEVERITY_CRITICAL = 'critical';

    public const BLOCK_TEMPORARY = 'temporary';

    public const BLOCK_PERMANENT = 'permanent';

    private const DEFAULT_BLOCK_DURATION = 3600;

    private const DEFAULT_MAX_FAILED_ATTEMPTS = 25;

    private const RETENTION_DAYS = 30;

    private const SEVERITY_ORDER = [
        self::SEVERITY_LOW => 1,
        self::SEVERITY_MEDIUM => 2,
        self::SEVERITY_HIGH => 3,
        self::SEVERITY_CRITICAL => 4,
    ];

    private readonly Config $config;

    /**
     * @var list<string>
     */
    private readonly array $trustedIps;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly BlockStoreInterface $store,
        array $config = []
    ) {
        $this->config = Config::fromArray($config);
        $this->trustedIps = $this->config->stringList('trusted_ips');
    }

    /**
     * Is this address blocked right now? Trusted addresses are never blocked.
     */
    public function isIpBlocked(string $ip): bool
    {
        if ($ip === '' || $this->isTrustedIp($ip)) {
            return false;
        }

        return $this->store->isPermanentlyBlocked($ip) || $this->store->isBlocked($ip);
    }

    /**
     * Temporary block with a severity-derived lifetime.
     */
    public function blockIp(
        string $ip,
        string $reason,
        string $severity = self::SEVERITY_MEDIUM,
        ?int $ttl = null
    ): void {
        if ($ip === '' || $this->isTrustedIp($ip)) {
            return;
        }

        $duration = $ttl ?? $this->durationFor($severity);

        $this->store->block($ip, $reason, $duration, self::BLOCK_TEMPORARY, $this->normalizeSeverity($severity));
    }

    /**
     * Permanent block — call this only from an explicit operator action.
     */
    public function blockPermanently(string $ip, string $reason, string $severity = self::SEVERITY_HIGH): void
    {
        if ($ip === '' || $this->isTrustedIp($ip)) {
            return;
        }

        $this->store->block($ip, $reason, null, self::BLOCK_PERMANENT, $this->normalizeSeverity($severity));
    }

    public function unblockIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $this->store->unblock($ip);

        return true;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function recordIncident(
        string $ip,
        string $type,
        string $description,
        string $severity = self::SEVERITY_MEDIUM,
        array $context = [],
        ?int $userId = null
    ): void {
        $this->store->logIncident($ip, $userId, $type, $description, $this->normalizeSeverity($severity), $context);
    }

    /**
     * Incidents for this address inside the window — the basis for
     * "journal once, not on every request".
     */
    public function recentIncidentCount(string $ip, int $windowSeconds = 600): int
    {
        return $this->store->countIncidents($ip, max(1, $windowSeconds));
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function recentIncidents(int $limit = 50): array
    {
        return $this->store->getRecentIncidents($limit);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function activeBlocks(int $limit = 100): array
    {
        return $this->store->getActiveBlocks($limit);
    }

    /**
     * Record one failed attempt (bad password, rejected API key, ...).
     *
     * @return int attempts recorded for this address, 0 when unsupported
     */
    public function recordFailedAttempt(string $ip): int
    {
        if ($ip === '' || $this->isTrustedIp($ip) || !$this->store instanceof FailedAttemptStoreInterface) {
            return 0;
        }

        return $this->store->recordFailedAttempt($ip);
    }

    public function failedAttempts(string $ip): int
    {
        if (!$this->store instanceof FailedAttemptStoreInterface) {
            return 0;
        }

        return $this->store->getFailedAttempts($ip);
    }

    public function clearFailedAttempts(string $ip): void
    {
        if ($this->store instanceof FailedAttemptStoreInterface) {
            $this->store->clearFailedAttempts($ip);
        }
    }

    /**
     * @return array<string, int> rows deleted per table
     */
    public function cleanup(int $retentionDays = self::RETENTION_DAYS): array
    {
        if (!$this->store instanceof MaintenanceStoreInterface) {
            return ['blocks' => 0, 'incidents' => 0, 'attempts' => 0];
        }

        return $this->store->cleanup($retentionDays);
    }

    /**
     * @return array<string, mixed>
     */
    public function stats(): array
    {
        return $this->store->getStats();
    }

    public function isTrustedIp(string $ip): bool
    {
        return $ip !== '' && CidrMatcher::isTrusted($ip, $this->trustedIps);
    }

    public function maxFailedAttempts(): int
    {
        return $this->config->nonNegativeInt('max_failed_attempts', self::DEFAULT_MAX_FAILED_ATTEMPTS);
    }

    /**
     * Block lifetime for a severity: base duration × multiplier.
     */
    public function durationFor(string $severity): int
    {
        $base = $this->config->nonNegativeInt('block_duration', self::DEFAULT_BLOCK_DURATION);

        if ($base === 0) {
            return 0;
        }

        $multiplier = $this->multipliers()[$this->normalizeSeverity($severity)] ?? 1.0;

        return max(1, (int) round($base * $multiplier));
    }

    public function severityRank(string $severity): int
    {
        return self::SEVERITY_ORDER[$this->normalizeSeverity($severity)] ?? 0;
    }

    public function normalizeSeverity(string $severity): string
    {
        $normalized = strtolower(trim($severity));

        return isset(self::SEVERITY_ORDER[$normalized]) ? $normalized : self::SEVERITY_MEDIUM;
    }

    /**
     * @return array<string, float>
     */
    private function multipliers(): array
    {
        $defaults = [
            self::SEVERITY_LOW => 0.5,
            self::SEVERITY_MEDIUM => 1.0,
            self::SEVERITY_HIGH => 4.0,
            self::SEVERITY_CRITICAL => 12.0,
        ];

        $configured = $this->config->map('severity_block_multipliers');

        foreach ($defaults as $severity => $value) {
            $candidate = $configured[$severity] ?? null;

            if (is_int($candidate) || is_float($candidate)) {
                $defaults[$severity] = (float) $candidate;
            } elseif (is_string($candidate) && is_numeric($candidate)) {
                $defaults[$severity] = (float) $candidate;
            }
        }

        return $defaults;
    }
}
