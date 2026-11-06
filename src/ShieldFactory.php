<?php

declare(strict_types=1);

namespace Deynekin\PhpShield;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Ip\IpResolver;
use Deynekin\PhpShield\Middleware\SecurityMiddleware;
use Deynekin\PhpShield\Middleware\Shield;
use Deynekin\PhpShield\RateLimiting\DatabaseRateLimiter;
use Deynekin\PhpShield\RateLimiting\RateLimiterInterface;
use Deynekin\PhpShield\RateLimiting\RedisRateLimiter;
use Deynekin\PhpShield\Storage\BlockStoreInterface;
use Deynekin\PhpShield\Storage\MysqlBlockStore;
use Deynekin\PhpShield\Support\Config;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationCache;
use Deynekin\PhpShield\ThreatIntel\CurlTransport;
use Deynekin\PhpShield\ThreatIntel\HttpTransportInterface;
use Deynekin\PhpShield\ThreatIntel\MysqlReputationCache;
use Deynekin\PhpShield\ThreatIntel\ReputationChecker;
use Deynekin\PhpShield\ThreatIntel\ReputationProviderInterface;
use Redis;

/**
 * Convenience factory: builds a ready-to-use Shield from configuration.
 */
class ShieldFactory
{
    /**
     * Build the shield with the bundled MySQL storage and the configured
     * rate limiter driver.
     *
     * @param array<string, mixed> $config
     */
    public static function create(array $config, \mysqli $mysqli, ?Redis $redis = null): Shield
    {
        $cfg = Config::fromArray($config);
        $autoMigrate = $cfg->bool('auto_migrate', true);

        $rateLimiter = match ($cfg->string('rate_limiter', 'database')) {
            'database' => new DatabaseRateLimiter($mysqli, $autoMigrate),
            'redis' => new RedisRateLimiter($redis ?? self::connectRedis($cfg), self::redisPrefix($cfg)),
            default => throw new ConfigurationException(
                "Configuration key 'rate_limiter' must be 'database' or 'redis'."
            ),
        };

        return new Shield(
            new SecurityMiddleware(new MysqlBlockStore($mysqli, $autoMigrate), $config),
            $rateLimiter,
            new IpResolver($cfg->stringList('trusted_proxies')),
            $config,
            self::createReputationChecker($config, $mysqli)
        );
    }

    /**
     * Build the shield from components you provide yourself.
     *
     * No MySQL and no Redis are required, which makes custom stores, SQLite
     * deployments and tests straightforward.
     *
     * @param array<string, mixed> $config
     */
    public static function createWithComponents(
        BlockStoreInterface $blockStore,
        RateLimiterInterface $rateLimiter,
        array $config = [],
        ?IpResolver $ipResolver = null,
        ?ReputationChecker $reputation = null
    ): Shield {
        return new Shield(
            new SecurityMiddleware($blockStore, $config),
            $rateLimiter,
            $ipResolver ?? new IpResolver(Config::fromArray($config)->stringList('trusted_proxies')),
            $config,
            $reputation
        );
    }

    /**
     * Build the AbuseIPDB layer from configuration.
     *
     * Providers are tried in the configured order: the list typically holds
     * abuseipdb.com first and abuseipdb.ru second, so one outage does not blind
     * the shield. A provider without an API key is skipped silently.
     *
     * @param array<string, mixed> $config
     */
    public static function createReputationChecker(
        array $config,
        ?\mysqli $mysqli = null,
        ?HttpTransportInterface $transport = null
    ): ?ReputationChecker {
        $cfg = Config::fromArray($config);

        if (!$cfg->nestedBool('ip_reputation.enabled', false)) {
            return null;
        }

        $providers = self::buildProviders($cfg, $transport ?? new CurlTransport());

        if ($providers === []) {
            return null;
        }

        $cache = $mysqli instanceof \mysqli
            ? new MysqlReputationCache($mysqli, $cfg->bool('auto_migrate', true))
            : new ArrayReputationCache();

        return new ReputationChecker(
            $providers,
            $cache,
            $cfg->nestedInt('ip_reputation.cache_ttl', 86400),
            $cfg->nestedInt('ip_reputation.circuit_breaker.failures', 5),
            $cfg->nestedInt('ip_reputation.circuit_breaker.cooldown', 120)
        );
    }

    /**
     * @return list<ReputationProviderInterface>
     */
    private static function buildProviders(Config $cfg, HttpTransportInterface $transport): array
    {
        $configured = $cfg->raw('ip_reputation.providers');

        if (!is_array($configured)) {
            return [];
        }

        $maxAgeDays = $cfg->nestedInt('ip_reputation.max_age_days', 90);
        $timeout = $cfg->nestedInt('ip_reputation.timeout', 2);

        $providers = [];

        foreach ($configured as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $name = $entry['name'] ?? 'abuseipdb.com';
            $baseUrl = $entry['base_url'] ?? AbuseIpDbProvider::COM_BASE_URL;
            $apiKey = $entry['api_key'] ?? '';
            $envName = $entry['api_key_env'] ?? '';

            $key = is_string($apiKey) ? $apiKey : '';

            if ($key === '' && is_string($envName) && $envName !== '') {
                $fromEnvironment = getenv($envName);
                $key = is_string($fromEnvironment) ? $fromEnvironment : '';
            }

            if ($key === '') {
                continue;
            }

            $providers[] = new AbuseIpDbProvider(
                $transport,
                $key,
                is_string($baseUrl) && $baseUrl !== '' ? $baseUrl : AbuseIpDbProvider::COM_BASE_URL,
                is_string($name) && $name !== '' ? $name : 'abuseipdb.com',
                $maxAgeDays,
                max(0.5, (float) $timeout)
            );
        }

        return $providers;
    }

    private static function redisPrefix(Config $cfg): string
    {
        $prefix = $cfg->map('redis')['prefix'] ?? 'phpshield:rl:';

        return is_string($prefix) && $prefix !== '' ? $prefix : 'phpshield:rl:';
    }

    private static function connectRedis(Config $cfg): Redis
    {
        if (!class_exists(Redis::class)) {
            throw new ConfigurationException(
                'The redis extension is required when rate_limiter is set to "redis".'
            );
        }

        $redisConfig = $cfg->map('redis');
        $host = $redisConfig['host'] ?? '127.0.0.1';
        $port = $redisConfig['port'] ?? 6379;
        $password = $redisConfig['password'] ?? null;
        $database = $redisConfig['database'] ?? 0;

        $client = new Redis();
        $client->connect(is_string($host) ? $host : '127.0.0.1', is_int($port) ? $port : 6379);

        if (is_string($password) && $password !== '') {
            $client->auth($password);
        }

        if (is_int($database) && $database > 0) {
            $client->select($database);
        }

        return $client;
    }
}
