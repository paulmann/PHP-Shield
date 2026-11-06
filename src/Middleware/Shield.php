<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Middleware;

use Deynekin\PhpShield\Detection\RuleFactory;
use Deynekin\PhpShield\Detection\RuleInterface;
use Deynekin\PhpShield\Ip\IpResolver;
use Deynekin\PhpShield\RateLimiting\RateLimiterInterface;
use Deynekin\PhpShield\Support\Config;
use Deynekin\PhpShield\Support\PayloadRedactor;
use Deynekin\PhpShield\ThreatIntel\IpReputation;
use Deynekin\PhpShield\ThreatIntel\ReputationChecker;

/**
 * Request shield: the single place where an inbound request is inspected before
 * the application handles it.
 *
 *   - Shield (this class) decides: rate limits, payload/header scanning, IP
 *     reputation, and the allow/deny/challenge verdict;
 *   - SecurityMiddleware owns state: blocks, incident journal, counters;
 *   - ReputationChecker adds outside knowledge (AbuseIPDB.com, AbuseIPDB.ru).
 *
 * Honest-visitor contract:
 *   - trusted addresses are never blocked and never counted;
 *   - a hard finding only blocks above block_threshold; anything merely
 *     suspicious is journalled at most once per address per window;
 *   - a reputation outage means "no data", never "deny".
 */
final class Shield
{
    private const REQUEST_URI_FIELD = '__request_uri';

    /**
     * @var list<RuleInterface>
     */
    private readonly array $rules;

    private readonly Config $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly SecurityMiddleware $middleware,
        private readonly RateLimiterInterface $rateLimiter,
        private readonly IpResolver $ipResolver,
        array $config = [],
        private readonly ?ReputationChecker $reputation = null
    ) {
        $this->config = Config::fromArray($config);
        $this->rules = RuleFactory::createFromConfig($config);
    }

    /**
     * Inspect a request.
     *
     * @param array<string, mixed> $requestData GET/POST payload
     * @param array<string, mixed> $server $_SERVER-like data
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}
     */
    public function inspect(
        array $requestData,
        array $server,
        string $endpoint = 'general',
        ?int $userId = null
    ): array {
        if (!$this->config->bool('enabled', true)) {
            return self::allow();
        }

        $ip = $this->ipResolver->resolve($server);

        if ($this->middleware->isTrustedIp($ip)) {
            return self::allow();
        }

        if ($this->middleware->isIpBlocked($ip)) {
            return self::deny(403, 'ip_blocked', 'This address is blocked by the request firewall.');
        }

        $failedAttempts = $this->escalateFailedAttempts($ip, $userId);

        if ($failedAttempts !== null) {
            return $failedAttempts;
        }

        $mode = $this->config->mode();

        $rateDecision = $this->inspectRateLimits($ip, $endpoint, $mode, $userId);

        if ($rateDecision !== null) {
            return $rateDecision;
        }

        $reputationDecision = $this->inspectReputation($ip, $mode, $userId);

        if ($reputationDecision !== null) {
            return $reputationDecision;
        }

        if ($this->config->bool('enable_content_scanning', true)) {
            $threats = $this->scanData($this->scanPayload($requestData, $server));
            $decision = $this->judgeThreats($threats, $ip, $mode, $userId, $requestData);

            if ($decision !== null) {
                return $decision;
            }
        }

        if ($this->config->bool('enable_header_scanning', true)) {
            $headerDecision = $this->inspectHeaders($server, $ip, $mode, $userId);

            if ($headerDecision !== null) {
                return $headerDecision;
            }
        }

        return self::allow();
    }

    /**
     * Boolean facade for call sites that only need the verdict.
     *
     * @param array<string, mixed> $requestData
     * @param array<string, mixed> $server
     */
    public function isRequestAllowed(
        array $requestData,
        array $server,
        string $endpoint = 'general',
        ?int $userId = null
    ): bool {
        return $this->inspect($requestData, $server, $endpoint, $userId)['blocked'] === false;
    }

    /**
     * Scan request data and return every matched threat.
     *
     * Values are tested as received and after URL decoding: percent-encoded
     * payloads (%3Cscript%3E) are the normal wire format of an attack even
     * though PHP hands us a decoded array.
     *
     * @param array<string, mixed> $data
     * @return list<array<string, mixed>>
     */
    public function scanData(array $data, string $prefix = ''): array
    {
        $seen = [];

        return $this->scan($data, $prefix, $seen);
    }

    public function middleware(): SecurityMiddleware
    {
        return $this->middleware;
    }

    /**
     * @return list<RuleInterface>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    public function getConfig(): Config
    {
        return $this->config;
    }

    /**
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}
     */
    private static function allow(): array
    {
        return ['blocked' => false, 'status' => 200, 'reason' => '', 'detail' => '', 'score' => 0, 'findings' => []];
    }

    /**
     * @param list<string> $findings
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}
     */
    private static function deny(int $status, string $reason, string $detail, int $score = 0, array $findings = []): array
    {
        return [
            'blocked' => true,
            'status' => $status,
            'reason' => $reason,
            'detail' => $detail,
            'score' => $score,
            'findings' => $findings,
        ];
    }

    /**
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}|null
     */
    private function escalateFailedAttempts(string $ip, ?int $userId): ?array
    {
        $max = $this->middleware->maxFailedAttempts();

        if ($max === 0 || $this->middleware->failedAttempts($ip) < $max) {
            return null;
        }

        $this->middleware->blockIp($ip, "Too many failed attempts ({$max})", SecurityMiddleware::SEVERITY_HIGH);
        $this->middleware->clearFailedAttempts($ip);
        $this->middleware->recordIncident(
            $ip,
            'too_many_failures',
            "Blocked after {$max} failed attempts",
            SecurityMiddleware::SEVERITY_HIGH,
            [],
            $userId
        );

        return self::deny(403, 'too_many_failures', 'Too many failed attempts from this address.');
    }

    /**
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}|null
     */
    private function inspectRateLimits(string $ip, string $endpoint, string $mode, ?int $userId): ?array
    {
        foreach ($this->config->rateLimits() as $name => $limit) {
            if ($this->rateLimiter->allow("rate:{$ip}:{$endpoint}:{$name}", $limit['limit'], $limit['window'])) {
                continue;
            }

            $this->middleware->recordIncident(
                $ip,
                'rate_limit',
                "Rate limit '{$name}' exceeded",
                SecurityMiddleware::SEVERITY_MEDIUM,
                ['endpoint' => $endpoint],
                $userId
            );

            if ($mode === 'monitor') {
                return null;
            }

            $this->middleware->blockIp(
                $ip,
                "Rate limit exceeded ({$name})",
                SecurityMiddleware::SEVERITY_MEDIUM,
                $this->config->nonNegativeInt('rate_limit_block_duration', 300)
            );

            return self::deny(429, 'rate_limited', 'Too many requests.');
        }

        return null;
    }

    /**
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}|null
     */
    private function inspectReputation(string $ip, string $mode, ?int $userId): ?array
    {
        if (!$this->reputation instanceof ReputationChecker || !$this->reputation->isEnabled()) {
            return null;
        }

        $reputation = $this->reputation->lookup($ip);

        if (!$reputation instanceof IpReputation || $reputation->isWhitelisted) {
            return null;
        }

        $blockScore = $this->score('ip_reputation.block_score', 75);
        $flagScore = $this->score('ip_reputation.flag_score', 25);
        $score = $reputation->abuseConfidenceScore;

        if ($score >= $blockScore) {
            $severity = $score >= 90 ? SecurityMiddleware::SEVERITY_CRITICAL : SecurityMiddleware::SEVERITY_HIGH;

            $this->middleware->recordIncident(
                $ip,
                'ip_reputation',
                "Abuse confidence score {$score} from {$reputation->provider}",
                $severity,
                $reputation->toArray(),
                $userId
            );

            if ($mode === 'monitor') {
                return null;
            }

            $this->middleware->blockIp($ip, "Bad IP reputation (score {$score}, {$reputation->provider})", $severity);

            return self::deny(
                403,
                'ip_reputation',
                'This address has a bad reputation.',
                $score,
                ['ip_reputation:' . $reputation->provider]
            );
        }

        if ($score >= $flagScore && $this->middleware->recentIncidentCount($ip, 600) === 0) {
            $this->middleware->recordIncident(
                $ip,
                'ip_reputation_flag',
                "Abuse confidence score {$score} from {$reputation->provider}",
                SecurityMiddleware::SEVERITY_LOW,
                $reputation->toArray(),
                $userId
            );
        }

        return null;
    }

    /**
     * @param list<array<string, mixed>> $threats
     * @param array<string, mixed> $requestData
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}|null
     */
    private function judgeThreats(array $threats, string $ip, string $mode, ?int $userId, array $requestData): ?array
    {
        if ($threats === []) {
            return null;
        }

        $score = 0;
        $findings = [];

        foreach ($threats as $threat) {
            $threatScore = $threat['score'] ?? 0;
            $score += is_int($threatScore) ? $threatScore : 0;

            $pattern = $threat['pattern'] ?? null;

            if (is_string($pattern)) {
                $findings[] = $pattern;
            }
        }

        $findings = array_values(array_unique($findings));
        $severity = match (true) {
            $score >= 80 => SecurityMiddleware::SEVERITY_CRITICAL,
            $score >= 40 => SecurityMiddleware::SEVERITY_HIGH,
            default => SecurityMiddleware::SEVERITY_MEDIUM,
        };

        $blockThreshold = $this->config->nonNegativeInt('block_threshold', 50);
        $context = ['threats' => $threats, 'payload' => PayloadRedactor::redact($requestData), 'score' => $score];

        if ($score >= $blockThreshold) {
            $this->middleware->recordIncident(
                $ip,
                'threat_detected',
                'Threats: ' . implode(', ', $findings),
                $severity,
                $context,
                $userId
            );

            // monitor: the finding is journaled so the operator can tune the
            // thresholds, but the request is never refused.
            if ($mode === 'monitor') {
                return null;
            }

            if ($mode === 'challenge') {
                return self::deny(403, 'challenge_required', 'Additional verification is required.', $score, $findings);
            }

            $this->middleware->blockIp($ip, "Threat detected (score: {$score})", $severity);

            return self::deny(403, 'threat_detected', 'The request matches a security rule.', $score, $findings);
        }

        // Suspicious but below the threshold: journal once per address per
        // 10 minutes so a noisy visitor cannot flood the journal.
        if ($score >= $this->config->nonNegativeInt('suspicious_threshold', 20)
            && $this->middleware->recentIncidentCount($ip, 600) === 0
        ) {
            $this->middleware->recordIncident(
                $ip,
                'threat_suspicious',
                'Request scored ' . $score . ' (below the block threshold)',
                SecurityMiddleware::SEVERITY_LOW,
                $context,
                $userId
            );
        }

        return null;
    }

    /**
     * @param array<string, mixed> $server
     * @return array{blocked: bool, status: int, reason: string, detail: string, score: int, findings: list<string>}|null
     */
    private function inspectHeaders(array $server, string $ip, string $mode, ?int $userId): ?array
    {
        $userAgent = $server['HTTP_USER_AGENT'] ?? '';

        if (!is_string($userAgent) || $userAgent === '') {
            return null;
        }

        foreach ($this->rules as $rule) {
            if ($rule->getCategory() !== 'headers' || !$rule->isEnabled()) {
                continue;
            }

            $result = $rule->check($userAgent, 'User-Agent');

            if (!$result['matched']) {
                continue;
            }

            $description = is_string($result['description'] ?? null) ? $result['description'] : 'Suspicious User-Agent';

            $this->middleware->recordIncident(
                $ip,
                'suspicious_ua',
                $description,
                SecurityMiddleware::SEVERITY_MEDIUM,
                ['ua' => mb_substr($userAgent, 0, 120)],
                $userId
            );

            if ($mode === 'monitor') {
                return null;
            }

            $this->middleware->blockIp($ip, 'Suspicious User-Agent', SecurityMiddleware::SEVERITY_MEDIUM);

            return self::deny(403, 'suspicious_user_agent', 'The client signature is not allowed.', 0, ['suspicious_header']);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $data
     * @param array<string, true> $seen
     * @return list<array<string, mixed>>
     */
    private function scan(array $data, string $prefix, array &$seen): array
    {
        $threats = [];

        foreach ($data as $key => $value) {
            $fieldName = $prefix !== '' ? $prefix . '.' . (string) $key : (string) $key;

            if (is_array($value)) {
                $threats = array_merge($threats, $this->scan($value, $fieldName, $seen));

                continue;
            }

            foreach ($this->candidateStrings($value) as $candidate) {
                foreach ($this->rules as $rule) {
                    if (!$rule->isEnabled()) {
                        continue;
                    }

                    // One finding per rule and field: the same payload encoded
                    // twice must not inflate the score.
                    $dedupeKey = $rule->getName() . '|' . $fieldName;

                    if (isset($seen[$dedupeKey])) {
                        continue;
                    }

                    $result = $rule->check($candidate, $fieldName);

                    if ($result['matched']) {
                        $seen[$dedupeKey] = true;
                        $threats[] = $result;
                    }
                }
            }
        }

        return $threats;
    }

    /**
     * @return list<string>
     */
    private function candidateStrings(mixed $value): array
    {
        if (is_int($value) || is_float($value)) {
            $value = (string) $value;
        }

        if (!is_string($value) || $value === '') {
            return [];
        }

        $candidates = [$value];

        foreach ([urldecode($value), stripslashes($value)] as $variant) {
            if ($variant !== $value && !in_array($variant, $candidates, true)) {
                $candidates[] = $variant;
            }
        }

        if (str_contains($value, "\0")) {
            $stripped = str_replace("\0", '', $value);

            if (!in_array($stripped, $candidates, true)) {
                $candidates[] = $stripped;
            }
        }

        return $candidates;
    }

    /**
     * @param array<string, mixed> $requestData
     * @param array<string, mixed> $server
     * @return array<string, mixed>
     */
    private function scanPayload(array $requestData, array $server): array
    {
        if (!$this->config->bool('scan_request_uri', true)) {
            return $requestData;
        }

        $uri = $server['REQUEST_URI'] ?? null;

        if (is_string($uri) && $uri !== '') {
            $requestData[self::REQUEST_URI_FIELD] = $uri;
        }

        return $requestData;
    }

    private function score(string $path, int $default): int
    {
        return max(0, min(100, $this->config->nestedInt($path, $default)));
    }
}
