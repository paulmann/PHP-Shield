<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Throwable;

/**
 * Turns one or more providers into a single "is this address known bad?" answer.
 *
 * Two modes, both safe on the request path:
 *
 *   - **async (default)** — `lookup()` never talks to the network. It answers
 *     from the cache and, on a miss, pushes the address into the queue for the
 *     worker (`tools/reputation-worker.php`, run from cron). The verdict for a
 *     new address therefore arrives with a later request, which is why the
 *     reputation layer is an addition to the local rules and not a blocker for
 *     the first visit.
 *   - **sync** — `lookup()` performs the call inline (bounded by `timeout`).
 *     Use it only for low-traffic endpoints or CLI tools.
 *
 * In both modes: answers are cached for `cacheTtl`; providers are tried in
 * order; `429` opens the advertised window; after `breakerFailures` consecutive
 * errors a provider is skipped for `breakerCooldown`; any failure means "no
 * data", never "block".
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
        private readonly int $breakerCooldown = 120,
        private readonly ?ReputationQueueInterface $queue = null,
        private readonly bool $async = false
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->providers !== [];
    }

    public function isAsync(): bool
    {
        return $this->async;
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

    /**
     * Answer for the request path. Never performs a network call in async mode.
     */
    public function lookup(string $ip): ?IpReputation
    {
        if (!$this->isEnabled() || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $cached = $this->cachedAnswer($ip);

        if ($cached instanceof IpReputation) {
            return $cached;
        }

        if ($this->async) {
            $this->queue?->push($ip);

            return null;
        }

        return $this->fetch($ip);
    }

    /**
     * Ask the providers now and store the answer.
     *
     * Provider errors are swallowed: this is the method the request path uses
     * in sync mode, and a broken provider must never break a visitor.
     */
    public function fetch(string $ip): ?IpReputation
    {
        try {
            return $this->fetchOrThrow($ip);
        } catch (Throwable $exception) {
            return null;
        }
    }

    /**
     * Like fetch(), but a provider failure is reported to the caller.
     *
     * The worker uses this variant to decide between "no opinion" (drop the
     * address) and "could not ask" (keep it for a retry with backoff).
     *
     * @throws ThreatIntelException
     */
    public function fetchOrThrow(string $ip): ?IpReputation
    {
        if (!$this->isEnabled() || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $cached = $this->cachedAnswer($ip);

        if ($cached instanceof IpReputation) {
            return $cached;
        }

        $now = time();
        $failure = null;
        $coolingDown = false;

        foreach ($this->providers as $provider) {
            $name = $provider->name();

            if ($this->breakerOpenUntil($name) > $now || $this->rateLimitedUntil($name) > $now) {
                $coolingDown = true;

                continue;
            }

            try {
                $reputation = $provider->lookup($ip);
            } catch (ThreatIntelException $exception) {
                $this->registerFailure($name, $exception, $now);
                $failure ??= $exception;

                continue;
            } catch (Throwable $exception) {
                // A provider must never break the caller; keep it for a retry.
                error_log('PHP-Shield reputation provider "' . $name . '": ' . $exception->getMessage());
                $failure ??= ThreatIntelException::unavailable($name, $exception->getMessage());

                continue;
            }

            $this->resetFailures($name);

            if (!$reputation instanceof IpReputation) {
                continue;
            }

            $this->cache($name, $reputation);

            return $reputation;
        }

        if ($failure instanceof ThreatIntelException) {
            throw $failure;
        }

        if ($coolingDown) {
            throw ThreatIntelException::unavailable('reputation', 'every provider is cooling down after failures');
        }

        return null;
    }

    public function queueSize(): int
    {
        return $this->queue?->size() ?? 0;
    }

    public function queue(): ?ReputationQueueInterface
    {
        return $this->queue;
    }

    private function cachedAnswer(string $ip): ?IpReputation
    {
        foreach ($this->providers as $provider) {
            $cached = $this->cache->get(self::CACHE_PREFIX . $provider->name() . ':' . $ip);

            if (!is_array($cached)) {
                continue;
            }

            $reputation = IpReputation::fromArray($cached);

            if ($reputation instanceof IpReputation) {
                return $reputation;
            }
        }

        return null;
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
