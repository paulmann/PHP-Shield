# PHP Shield — Wiki

## Table of contents

1. [What PHP Shield is](#what-php-shield-is)
2. [Installation](#installation)
3. [Entry points and the decision array](#entry-points-and-the-decision-array)
4. [Configuration reference](#configuration-reference)
5. [IP reputation: AbuseIPDB.com and AbuseIPDB.ru](#ip-reputation-abuseipdbcom-and-abuseipdbru)
6. [Detection rules and scoring](#detection-rules-and-scoring)
7. [Modes, thresholds and block lifetimes](#modes-thresholds-and-block-lifetimes)
8. [State: blocks, incidents, failed attempts](#state-blocks-incidents-failed-attempts)
9. [Rate limiting backends](#rate-limiting-backends)
10. [Admin interface](#admin-interface)
11. [Reverse proxies and client IP](#reverse-proxies-and-client-ip)
12. [Production deployment checklist](#production-deployment-checklist)
13. [False positives and tuning](#false-positives-and-tuning)
14. [Testing and CI](#testing-and-ci)
15. [Troubleshooting](#troubleshooting)
16. [Upgrading from SecurityMiddleware 1.x](#upgrading-from-securitymiddleware-1x)

---

## What PHP Shield is

A request firewall for PHP applications. One call decides whether a request may proceed, and records why:

- **local detection** of SQL injection, XSS, command injection, path traversal, file inclusion and scanner signatures;
- **IP reputation** from AbuseIPDB.com and AbuseIPDB.ru with cache, quotas and a circuit breaker;
- **rate limiting** per address and endpoint (database or Redis);
- **state**: temporary and permanent blocks, an incident journal, failed-attempt counters, retention cleanup and statistics;
- **an admin dashboard** with CSRF protection and masked configuration.

It is not a replacement for prepared statements, output escaping, CSP, authentication or session security. It buys time and visibility; it does not fix application defects.

## Installation

```bash
composer require paulmann/php-shield
```

Requirements: PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`. Optional: `ext-mysqli` (MySQL storage and dashboard), `ext-redis` (Redis limiter), `ext-curl` (reputation lookups).

Tables are created automatically (`auto_migrate`). In production, apply `migrations/schema.sql` once and disable auto-migration so no DDL runs on the request path.

## Entry points and the decision array

```php
$decision = $shield->inspect($requestData, $server, $endpoint = 'general', $userId = null);
$allowed  = $shield->isRequestAllowed($requestData, $server);   // boolean facade
```

| Key | Type | Meaning |
|---|---|---|
| `blocked` | bool | may the request proceed |
| `status` | int | HTTP status to send (403 / 429 / 200) |
| `reason` | string | `ip_blocked`, `too_many_failures`, `rate_limited`, `ip_reputation`, `threat_detected`, `challenge_required`, `suspicious_user_agent` |
| `detail` | string | human-readable explanation, safe to log |
| `score` | int | accumulated score of the findings |
| `findings` | string[] | rule names or `ip_reputation:<provider>` |

The order of checks is fixed and intentional:

1. master switch (`enabled`) → allow;
2. trusted address → allow (never blocked, never counted);
3. active block → deny 403 `ip_blocked`;
4. failed-attempt counter over the limit → block and deny 403;
5. rate limits → deny 429 (or journal only in `monitor`);
6. IP reputation → block / journal / ignore;
7. payload scanning → score, journal, block or allow;
8. header scanning (User-Agent) → journal or block;
9. allow.

## Configuration reference

`config/default.php` is the annotated reference. Keys that change behaviour:

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | master switch |
| `mode` | `monitor` | `monitor`, `challenge`, `block`; an unknown value throws |
| `block_threshold` | `50` | score that blocks in `block` mode |
| `challenge_threshold` | `30` | score refused in `challenge` mode |
| `suspicious_threshold` | `20` | score journaled once per 10 minutes, never blocked |
| `block_duration` | `3600` | base lifetime, multiplied by severity |
| `rate_limit_block_duration` | `300` | block applied when a rate limit breaks |
| `max_failed_attempts` | `25` | 0 disables the escalation |
| `severity_block_multipliers` | low 0.5 / medium 1 / high 4 / critical 12 | lifetime per severity |
| `auto_migrate` | `true` | false = apply `schema.sql` yourself |
| `trusted_ips` | loopback | every address here **bypasses all checks** |
| `trusted_proxies` | empty | only these may set `X-Forwarded-For` / `X-Real-IP` |
| `rate_limits` | minute/hour/day | `['limit' => int, 'window' => seconds]` per entry |
| `enabled_rules` | all six | unknown names throw `ConfigurationException` |
| `rules.<name>.enabled` | `true` | per-rule switch |
| `scan_request_uri` | `true` | scan `REQUEST_URI` as well as GET/POST |
| `ip_reputation.*` | disabled | see the next section |
| `admin.*` | credentials | `password_hash`, `session_timeout`, `cookie_samesite`, `cookie_secure` |
| `rate_limiter` | `database` | `database` or `redis` |

Configuration is read through a typed accessor: a wrong type, an unknown mode or an unknown rule name raises `Deynekin\PhpShield\Exception\ConfigurationException` instead of silently disabling protection.

## IP reputation: AbuseIPDB.com and AbuseIPDB.ru

Both services speak the same API v2 contract, so the library ships one client (`ThreatIntel\AbuseIpDbProvider`) parameterised by base URL.

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'block_score' => 75,
    'flag_score' => 25,
    'cache_ttl' => 86400,
    'max_age_days' => 90,
    'timeout' => 2,
    'circuit_breaker' => ['failures' => 5, 'cooldown' => 120],
    'providers' => [
        ['name' => 'abuseipdb.com', 'base_url' => 'https://api.abuseipdb.com/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_API_KEY'],
        ['name' => 'abuseipdb.ru',  'base_url' => 'https://abuseipdb.ru/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_RU_API_KEY'],
    ],
];
```

Decision rules:

| abuseConfidenceScore | Result |
|---|---|
| `>= block_score` and not whitelisted | incident + block (severity `high`, `critical` from 90) + `403 ip_reputation` |
| `>= flag_score` | one `ip_reputation_flag` incident per 10 minutes, request allowed |
| below `flag_score` | ignored |
| `isWhitelisted = true` | always ignored |

Operational guarantees:

- **cache first** — a hit costs no network and is shared through `php_shield_ip_reputation`;
- **private and reserved addresses are never queried**;
- **provider fallback** — a failing provider passes the question to the next one;
- **quota discipline** — `429` opens a window taken from `Retry-After` or `X-RateLimit-Reset`, and nothing is retried in-process;
- **circuit breaker** — after N consecutive errors the provider is skipped for the cooldown;
- **fail open** — a timeout, a 5xx or a bad key never blocks a visitor; the shield continues with local rules.

Testing the integration:

```bash
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
ABUSEIPDB_RU_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8 --provider=ru
```

## Detection rules and scoring

| Rule | Category | Scores | Examples |
|---|---|---|---|
| `sql_injection` | injection | 50 `UNION SELECT`, 80 `DROP TABLE`, 60 `SLEEP(`, 30 tautology | `1' UNION SELECT …` |
| `xss` | xss | 90 `<script>`, 70 `javascript:`, 60 event handler, 65 `eval(` | `<img onerror=…>` |
| `command_injection` | injection | 85 `system(`, 75 `; cat`, 70 `\| whoami`, 60 backticked command | `; cat /etc/passwd` |
| `path_traversal` | path | 95 `/etc/shadow`, 90 `/etc/passwd`, 60 repeated `../` | `../../etc/passwd` |
| `file_inclusion` | inclusion | 85 `php://filter`, 80 remote include, 75 `php://input` | `php://filter/…` |
| `suspicious_header` | headers | 70 sqlmap/nikto/nmap, 60 masscan/zgrab | `sqlmap/1.7` |

Scoring model:

- rules return the first matching pattern per value, with its score;
- scores from different rules and fields are summed;
- the sum is compared against `block_threshold`;
- one finding per rule per field is recorded, so encoding a payload twice does not double the score;
- values are tested raw, URL-decoded, with `stripslashes` applied and with NUL bytes removed.

Custom rules extend `AbstractRule` and are registered at runtime:

```php
RuleFactory::register('my_rule', MyRule::class);
```

## Modes, thresholds and block lifetimes

| Mode | Hard finding | Suspicious | Rate limit |
|---|---|---|---|
| `monitor` | journaled | journaled once / 10 min | journaled |
| `challenge` | 403 `challenge_required`, no block | journaled | block + 429 |
| `block` | block + 403 | journaled | block + 429 |

Lifetime is `block_duration` × multiplier (see `severity_block_multipliers`). A permanent block is never automatic: use the dashboard or `blockPermanently()` from an operator action.

## State: blocks, incidents, failed attempts

```php
$state = $shield->middleware();

$state->isIpBlocked($ip);
$state->blockIp($ip, $reason, $state::SEVERITY_HIGH);      // temporary
$state->blockPermanently($ip, $reason);                    // operator decision
$state->unblockIp($ip);
$state->recordIncident($ip, $type, $description, $severity, $context, $userId);
$state->recentIncidentCount($ip, 600);
$state->recentIncidents(50);
$state->activeBlocks(100);
$state->recordFailedAttempt($ip);
$state->stats();
$state->cleanup(30);
```

Tables: `php_shield_ip_blocks`, `php_shield_incidents`, `php_shield_failed_attempts`, `php_shield_rate_limit`, `php_shield_ip_reputation`.

Scheduling maintenance:

```sql
DELETE FROM php_shield_ip_blocks       WHERE block_type = 'temporary' AND expires_at <= NOW();
DELETE FROM php_shield_incidents       WHERE occurred_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
DELETE FROM php_shield_failed_attempts WHERE last_attempt_at < DATE_SUB(NOW(), INTERVAL 1 DAY);
DELETE FROM php_shield_rate_limit      WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 DAY);
DELETE FROM php_shield_ip_reputation   WHERE expires_at <= NOW();
```

All expiries are computed by the database (`NOW()` / `DATE_ADD`), never by PHP, so a PHP/MySQL time-zone difference cannot expire a fresh block.

## Rate limiting backends

**DatabaseRateLimiter** — a counter table. Two statements (count, insert), so a burst can overshoot by the number of in-flight requests. Fine for low and medium traffic; call `prune()` on a schedule.

**RedisRateLimiter** — atomic `INCR` + `EXPIRE`, recommended for concurrency. Fails open (logged) if Redis is unreachable.

Both implement `RateLimiterInterface`; provide your own to integrate an existing limiter.

## Admin interface

`public/admin/index.php`:

- login with `admin.username` + `admin.password_hash`;
- statistics, active blocks, manual block/unblock;
- configuration dump with credentials masked;
- CSRF token on every state-changing form, `SameSite=Strict` cookie, session id regenerated on login, 5 failures → 5 minute lockout.

Protect the directory at the web-server level (IP allowlist, VPN, HTTP auth). The form is only as strong as the password.

## Reverse proxies and client IP

`X-Forwarded-For` is honoured only when `REMOTE_ADDR` is in `trusted_proxies`, and the chain is read **from right to left**, skipping trusted hops:

```
X-Forwarded-For: 1.2.3.4, 203.0.113.9      (client-supplied, added by nginx)
REMOTE_ADDR:     10.0.0.5                  (trusted proxy)
→ client = 203.0.113.9
```

Reading the left-most entry instead would let any client choose its own address — and, with a `trusted_ips` entry matching it, bypass the whole shield.

## Production deployment checklist

1. `mode = monitor` for several days.
2. Review `php_shield_incidents`; tune thresholds; disable noisy rules.
3. Apply `migrations/schema.sql`, set `auto_migrate = false`.
4. Move the rate limiter to Redis.
5. Fill `trusted_proxies`; keep `trusted_ips` minimal.
6. Set a strong `admin.password_hash`, protect the dashboard URL.
7. Schedule cleanup and `prune()`.
8. Enable `ip_reputation` (AbuseIPDB.com, AbuseIPDB.ru as fallback).
9. Add `SecurityHeaders::send()` early in the request.
10. Switch to `block` mode and watch the 403/429 rate.

## False positives and tuning

1. Find the incident: rule, score, field.
2. In `monitor` mode lower the rule score, disable the rule, or refine its pattern.
3. Check whether the payload is legitimate content — a security site that accepts abuse reports will quote `' UNION SELECT` on purpose; keep such forms in `monitor` per endpoint.
4. Never raise `block_threshold` blindly: it also hides real attacks.

## Testing and CI

```bash
composer test        # PHPUnit, no services required
composer phpstan     # level max
composer cs-check    # coding standard

MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
```

The database self-test creates its own tables in the given database, only touches rows it created and never drops a database.

CI: PHP 8.1 – 8.5, PHPUnit, PHPStan level max, coding standard, syntax check of every file.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| everything is allowed | `mode = monitor` | set `block` |
| `ConfigurationException: Unknown mode` | typo in `mode` | use `monitor`, `challenge` or `block` |
| blocks disappear immediately | PHP and MySQL clocks differ | already handled: expiries use the database clock; check `auto_migrate` |
| reputation never blocks | `ip_reputation.enabled` false, no key, score below `block_score`, or `mode = monitor` | check `ABUSEIPDB_API_KEY`, thresholds, mode |
| reputation blocks nobody after an outage | circuit breaker is open | wait for `circuit_breaker.cooldown` |
| `403` for a legitimate client behind a proxy | `trusted_proxies` empty | add the proxy network |
| old tables without `severity` | upgrade from 1.x | `auto_migrate` adds the column, or run the `ALTER` in `schema.sql` |

## Upgrading from SecurityMiddleware 1.x

2.0 is a deliberate break:

- the decision engine moved to `Middleware\Shield`; `inspect()` replaces the old boolean flow and returns a decision array;
- `SecurityMiddleware` now owns state only (blocks, incidents, counters, cleanup, stats);
- `ShieldFactory::create()` returns a `Shield`;
- `BlockStoreInterface` gained `countIncidents()`, `getRecentIncidents()` and a `$severity` argument on `block()`;
- severity-based lifetimes replace the fixed high-score duration;
- AbuseIPDB reputation is new.

See `CHANGELOG.md` for the full list.
