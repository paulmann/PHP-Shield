<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Throwable;

/**
 * Turns one or more providers into a single "is this address known bad?" answer.
 *
 * Design rules (taken from the production checklist of the abuseipdb.ru
 * project, where a reputation lookup must never hurt an honest visitor):
 *
 *   - answers are cached for `cacheTtl` seconds, so a burst costs one query;
 *   - providers are tried in order: abuseipdb.com first, abuseipdb.ru as the
 *     fallback (or the other way round) — one outage does not blind the site;
 *   - a provider that fails `breakerFailures` times in a row is skipped for
 *     `breakerCooldown` seconds;
 *   - `429` is never retried in-process: the advertised retry window is
 *     honoured for every following lookup;
 *   - any failure means "no data", never "block": the shield keeps working with
 *     its local rules.
 */
final class ReputationChecker
{
    private const CACHE_PREFIX = 'reputation:';
    private const BREAKER_PREFIX = 'breaker:';
    private const RATE_LIMIT_PREFIX = 'ratelimit:';

    /**
     * @param list<ReputationProviderInterface> $providers
     */
    public function __construct(
        private readonly array $providers,
        private readonly ReputationCacheInterface $cache,
        private readonly int $cacheTtl = 86400,
        private readonly int $breakerFailures = 5,
        private readonly int $breakerCooldown = 120
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->providers !== [];
    }

    /**
     * @return list<string> provider names in priority order
     */
    public function providerNames(): array
    {
        $names = [];

        foreach ($this->providers as $provider) {
            $names[] = $provider->name();
        }

        return $names;
    }

    public function lookup(string $ip): ?IpReputation
    {
        if ($this->providers === [] || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $now = time();

        foreach ($this->providers as $provider) {
            $name = $provider->name();

            $cached = $this->fromCache($name, $ip);

            if ($cached instanceof IpReputation) {
                return $cached;
            }

            if ($this->breakerOpenUntil($name) > $now || $this->rateLimitedUntil($name) > $now) {
                continue;
            }

            try {
                $reputation = $provider->lookup($ip);
            } catch (ThreatIntelException $exception) {
                $this->registerFailure($name, $exception, $now);

                continue;
            } catch (Throwable $exception) {
                // A provider must never break the request path.
                error_log('PHP-Shield reputation provider "' . $name . '": ' . $exception->getMessage());

                continue;
            }

            $this->resetFailures($name);

            if (!$reputation instanceof IpReputation) {
                continue;
            }

            $this->cache($name, $reputation);

            return $reputation;
        }

        return null;
    }

    private function fromCache(string $provider, string $ip): ?IpReputation
    {
        $cached = $this->cache->get(self::CACHE_PREFIX . $provider . ':' . $ip);

        if (!is_array($cached)) {
            return null;
        }

        return IpReputation::fromArray($cached);
    }

    private function cache(string $provider, IpReputation $reputation): void
    {
        $this->cache->set(
            self::CACHE_PREFIX . $provider . ':' . $reputation->ip,
            $reputation->toArray(),
            max(1, $this->cacheTtl)
        );
    }

    private function registerFailure(string $provider, ThreatIntelException $exception, int $now): void
    {
        $retryAfter = $exception->getRetryAfter();

        if ($retryAfter > 0) {
            $this->cache->set(self::RATE_LIMIT_PREFIX . $provider, $now + $retryAfter, $retryAfter + 1);

            return;
        }

        $failures = $this->failureCount($provider) + 1;
        $this->cache->set(self::BREAKER_PREFIX . $provider . ':failures', $failures, max(60, $this->breakerCooldown * 4));

        if ($failures >= max(1, $this->breakerFailures)) {
            $this->cache->set(
                self::BREAKER_PREFIX . $provider . ':open_until',
                $now + max(1, $this->breakerCooldown),
                max(1, $this->breakerCooldown)
            );
        }
    }

    private function resetFailures(string $provider): void
    {
        $this->cache->set(self::BREAKER_PREFIX . $provider . ':failures', 0, 60);
    }

    private function failureCount(string $provider): int
    {
        $value = $this->cache->get(self::BREAKER_PREFIX . $provider . ':failures');

        return is_int($value) ? $value : 0;
    }

    private function breakerOpenUntil(string $provider): int
    {
        $value = $this->cache->get(self::BREAKER_PREFIX . $provider . ':open_until');

        return is_int($value) ? $value : 0;
    }

    private function rateLimitedUntil(string $provider): int
    {
        $value = $this->cache->get(self::RATE_LIMIT_PREFIX . $provider);

        return is_int($value) ? $value : 0;
    }
}
