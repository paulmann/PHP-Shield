# Configuration reference

`../config/default.php` is the annotated reference; every default below is quoted from it. Read
configuration through `Support\Config` — a wrong type, an unknown mode or an unknown rule name raises
`Deynekin\PhpShield\Exception\ConfigurationException` instead of silently disabling protection.

## Switches and modes

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | master switch for the whole shield |
| `mode` | `monitor` | `monitor`, `challenge`, `block`; any other value throws |
| `enable_content_scanning` | `true` | scan GET/POST payloads |
| `enable_header_scanning` | `true` | scan request headers (User-Agent) |
| `scan_request_uri` | `true` | also scan `REQUEST_URI`: parameters that never reach the application still hit the server |

## Thresholds and durations

| Key | Default | Notes |
|---|---|---|
| `block_threshold` | `50` | score that blocks in `block` mode |
| `challenge_threshold` | `30` | score refused in `challenge` mode |
| `suspicious_threshold` | `20` | journaled once per 10 minutes, never blocked |
| `block_duration` | `3600` | base lifetime in seconds, multiplied by the severity |
| `rate_limit_block_duration` | `300` | block applied when a rate limit breaks |
| `max_failed_attempts` | `25` | failed logins before an address is blocked once; `0` disables |

`severity_block_multipliers` maps severity to a lifetime multiplier: `low` 0.5, `medium` 1.0, `high`
4.0, `critical` 12.0. With the default `block_duration` that is 30 minutes, 1 hour, 4 hours and 12
hours. A permanent block is never automatic.

## Addresses

| Key | Default | Notes |
|---|---|---|
| `trusted_ips` | `127.0.0.1`, `::1` | every address here bypasses **all** checks and is never counted |
| `trusted_proxies` | empty | only these may set `X-Forwarded-For` / `X-Real-IP`; the chain is read right to left |

Keep both lists short. A `trusted_ips` entry that a client can reach through a spoofed forwarded
header is a full bypass — that defect existed in 1.x and is covered by `IpResolverTest` now.

## Rate limits

```php
'rate_limits' => [
    'minute' => ['limit' => 60,    'window' => 60],
    'hour'   => ['limit' => 1000,  'window' => 3600],
    'day'    => ['limit' => 10000, 'window' => 86400],
],
```

Each entry is `['limit' => int, 'window' => seconds]` and is applied per address and endpoint. See
[Rate limiting](07-Rate-Limiting.md) for the backends.

## Detection rules

| Key | Default | Notes |
|---|---|---|
| `enabled_rules` | all six | `sql_injection`, `xss`, `command_injection`, `path_traversal`, `file_inclusion`, `suspicious_header`; an unknown name throws |
| `rules.<name>.enabled` | `true` | per-rule switch for tuning without editing the registry |

Rule scores and patterns: [Detection rules](03-Detection-Rules.md).

## IP reputation

| Key | Default | Notes |
|---|---|---|
| `ip_reputation.enabled` | `false` | reputation costs quota and network time; enable it deliberately |
| `ip_reputation.block_score` | `75` | `abuseConfidenceScore` that blocks |
| `ip_reputation.flag_score` | `25` | score that is only journaled |
| `ip_reputation.cache_ttl` | `86400` | seconds a cached answer is trusted |
| `ip_reputation.max_age_days` | `90` | `maxAgeInDays` sent to the API |
| `ip_reputation.timeout` | `2` | per-request timeout in seconds |
| `ip_reputation.circuit_breaker.failures` | `5` | consecutive errors before a provider is skipped |
| `ip_reputation.circuit_breaker.cooldown` | `120` | seconds the broken provider is skipped |
| `ip_reputation.providers[]` | `.com`, then `.ru` | tried in order; keys come from `api_key_env` |

Full behaviour, quota handling and the fallback ladder: [IP reputation](04-IP-Reputation.md).

## Storage and rate limiter

| Key | Default | Notes |
|---|---|---|
| `auto_migrate` | `true` | create tables on first use; set `false` in production and apply `../migrations/schema.sql` |
| `rate_limiter` | `database` | `database` or `redis`; any other value throws |
| `redis.host`, `redis.port` | `127.0.0.1`, `6379` | connection for `RedisRateLimiter` |
| `redis.password` | `null` | masked in the dashboard dump |
| `redis.database` | `0` | Redis database index |
| `redis.prefix` | `phpshield:rl:` | key prefix |

## Admin

| Key | Default | Notes |
|---|---|---|
| `admin.enabled` | `true` | dashboard availability |
| `admin.username` | `admin` | login name |
| `admin.password_hash` | empty | `password_hash()` output; empty **disables login entirely** |
| `admin.session_name` | `php_shield_admin` | session cookie name |
| `admin.session_timeout` | `3600` | idle timeout in seconds |
| `admin.cookie_samesite` | `Strict` | `Strict`, `Lax` or `None` |
| `admin.cookie_secure` | `null` | `null` decides from `$_SERVER['HTTPS']` |

## A production-shaped configuration

```php
$config = require 'config/default.php';

$config['mode'] = 'block';
$config['auto_migrate'] = false;
$config['rate_limiter'] = 'redis';
$config['trusted_ips'] = ['10.20.0.0/24'];          // your own network, nothing else
$config['trusted_proxies'] = ['10.0.0.5'];          // exactly the proxies in front of PHP
$config['ip_reputation'] = array_merge($config['ip_reputation'], [
    'enabled' => true,
]);
$config['admin']['password_hash'] = getenv('PHP_SHIELD_ADMIN_HASH');
```

Keys never live in the file: `api_key_env` names an environment variable, and the password hash comes
from the environment or a file outside the document root.
