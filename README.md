![PHP Shield — modular request firewall for PHP](assets/social-preview.png)

# PHP Shield

**Modular request firewall for PHP**: local threat detection, IPv4/IPv6 reputation (AbuseIPDB.com and AbuseIPDB.ru), rate limiting, IP blocking with severity-based lifetimes, an incident journal and an admin dashboard.

**English** · [Русский](README.ru.md) · [Deutsch](README.de.md) · [Español](README.es.md) · [中文](README.zh.md) · [हिन्दी](README.hi.md)

[![CI](https://github.com/paulmann/PHP-Shield/actions/workflows/ci.yml/badge.svg)](https://github.com/paulmann/PHP-Shield/actions)
[![PHP Version](https://img.shields.io/badge/php-8.1--8.5-blue)](https://php.net)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%20max-brightgreen)](phpstan.neon)
[![Tests](https://img.shields.io/badge/tests-120-brightgreen)](tests)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue)](https://github.com/paulmann/PHP-Shield/wiki)

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [The decision array](#the-decision-array)
- [IP reputation: AbuseIPDB.com and AbuseIPDB.ru](#ip-reputation-abuseipdbcom-and-abuseipdbru)
- [Detection rules](#detection-rules)
- [Modes and block lifetimes](#modes-and-block-lifetimes)
- [Rate limiting](#rate-limiting)
- [State API](#state-api)
- [Admin dashboard](#admin-dashboard)
- [Reverse proxies and client IP](#reverse-proxies-and-client-ip)
- [Architecture](#architecture)
- [Testing](#testing)
- [Production checklist](#production-checklist)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

## What it does

One entry point, `Deynekin\PhpShield\Middleware\Shield::inspect()`, answers a single question: **may this request proceed, and if not, why?**

It combines four layers:

| Layer | Class | Responsibility |
|---|---|---|
| Decision | `Middleware\Shield` | rate limits, payload/header scanning, IP reputation, the verdict |
| State | `Middleware\SecurityMiddleware` | blocks, incident journal, failed-attempt counters, cleanup, statistics |
| Detection | `Detection\*` | pluggable rules that score a payload |
| Knowledge | `ThreatIntel\*` | AbuseIPDB.com / AbuseIPDB.ru reputation with cache and circuit breaker |

Two rules shape every decision:

- **A single finding never bans anyone.** Scores accumulate and only a total above `block_threshold` blocks. An operator, not a regex, decides on a permanent block.
- **Nothing fails closed on infrastructure trouble.** A database or API outage means "no data", not "deny" — see [ADR-006](docs/adr.md).

What the shield is **not**: a replacement for prepared statements, output escaping, CSP, authentication or session security. It buys time and visibility; it does not fix application defects.

## Requirements

- PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`
- Optional: `ext-mysqli` (MySQL storage, admin), `ext-redis` (Redis rate limiter), `ext-curl` (IP reputation)

## Install

```bash
composer require paulmann/php-shield
```

## Quick start

```php
<?php
require 'vendor/autoload.php';

use Deynekin\PhpShield\ShieldFactory;

$config = require 'vendor/paulmann/php-shield/config/default.php';
$config['mode'] = 'monitor';              // start safe, switch to "block" after tuning

$mysqli = new mysqli('127.0.0.1', 'user', 'pass', 'dbname');
$shield = ShieldFactory::create($config, $mysqli);

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');

if ($decision['blocked']) {
    http_response_code($decision['status']);
    header('Content-Type: application/json');
    exit(json_encode(['error' => $decision['reason'], 'detail' => $decision['detail']]));
}

// Application logic continues...
```

No MySQL? Build the shield from components instead — local detection, headers and statistics keep working:

```php
$shield = ShieldFactory::createWithComponents(
    $blockStore,                                  // your BlockStoreInterface implementation
    new \Deynekin\PhpShield\RateLimiting\RedisRateLimiter($redis),
    $config
);
```

## The decision array

`inspect()` returns:

```php
[
    'blocked'  => true,                 // may the request proceed?
    'status'   => 403,                  // HTTP status to send
    'reason'   => 'threat_detected',    // machine-readable code
    'detail'   => '...',                // human-readable text
    'score'    => 90,                   // accumulated score
    'findings' => ['xss', 'sql_injection'],
]
```

Reasons: `ip_blocked`, `too_many_failures`, `rate_limited`, `ip_reputation`, `threat_detected`, `challenge_required`, `suspicious_user_agent`.

The order of checks is fixed and intentional: master switch → trusted address (never blocked, never counted) → active block → failed-attempt counter → rate limits → IP reputation → payload scan → header scan → allow.

If you only need a boolean, call `isRequestAllowed()` with the same arguments.

## IP reputation: AbuseIPDB.com and AbuseIPDB.ru

Both services implement the same API v2 contract (`/check`, `Key:` header, identical envelopes), so one client serves both and the checker tries them in order.

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'block_score' => 75,   // abuseConfidenceScore that blocks
    'flag_score' => 25,    // score that is only journaled
    'cache_ttl' => 86400,
    'timeout' => 2,
    'providers' => [
        ['name' => 'abuseipdb.com', 'base_url' => 'https://api.abuseipdb.com/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_API_KEY'],
        ['name' => 'abuseipdb.ru',  'base_url' => 'https://abuseipdb.ru/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_RU_API_KEY'],
    ],
];
```

```bash
export ABUSEIPDB_API_KEY=your-key          # or put the key in the config, never in git
php tools/live-abuseipdb.php 8.8.8.8
```

Behaviour that matters in production:

- answers are cached for `cache_ttl` seconds — a burst costs one query, and only public addresses are ever asked about;
- the first provider that answers wins; if it fails, the next one is tried;
- `429` is never retried in-process: the advertised window is honoured for all following lookups;
- after `circuit_breaker.failures` consecutive errors a provider is skipped for `cooldown` seconds;
- a `null` answer, a timeout or a quota error never blocks a request;
- in `monitor` mode a high score is journaled but not blocked.

## Detection rules

| Rule | Category | Score | Notes |
|---|---|---|---|
| `sql_injection` | injection | 25–80 | `UNION SELECT`, stacked queries, `SLEEP`, tautologies |
| `xss` | xss | 40–90 | script/iframe/object tags, event handlers, `javascript:` |
| `command_injection` | injection | 60–85 | `system()` family, pipes to commands, command backticks |
| `path_traversal` | path | 60–95 | repeated `../`, `/etc/passwd`, `.ssh`, `/proc/self` |
| `file_inclusion` | inclusion | 60–85 | remote includes, `php://` wrappers |
| `suspicious_header` | headers | 60–70 | scanner User-Agents (sqlmap, nikto, nmap, …) |

Values are scanned both as received and after URL decoding, plus the raw `REQUEST_URI`, so `%3Cscript%3E` is caught. One finding per rule and field is recorded, so a twice-encoded payload cannot inflate its score.

### Custom rules

```php
use Deynekin\PhpShield\Detection\AbstractRule;
use Deynekin\PhpShield\Detection\RuleFactory;

final class MyRule extends AbstractRule
{
    public function getName(): string { return 'my_rule'; }
    public function getCategory(): string { return 'custom'; }

    public function check(string $value, string $fieldName): array
    {
        return $this->match('/evil/i', $value, $fieldName, 45, 'Custom evil pattern');
    }
}

RuleFactory::register('my_rule', MyRule::class);
```

## Modes and block lifetimes

| Mode | Behaviour |
|---|---|
| `monitor` | everything is journaled, nothing is blocked |
| `challenge` | hard findings are refused with 403 `challenge_required` and not blocked |
| `block` | hard findings block the address for a severity-derived lifetime |

Lifetime = `block_duration` × `severity_block_multipliers`:

| Severity | Multiplier | Default lifetime |
|---|---|---|
| `low` | 0.5 | 30 min |
| `medium` | 1 | 1 h |
| `high` | 4 | 4 h |
| `critical` | 12 | 12 h |

Rate limiting has its own short window (`rate_limit_block_duration`, 300 s) so a burst from a shared/NAT address cannot lock out a whole office. A permanent block is never automatic: it is an operator action in the dashboard or `blockPermanently()`.

## Rate limiting

| Backend | How it counts | Use it when |
|---|---|---|
| `DatabaseRateLimiter` | two statements (count, insert) on `php_shield_rate_limit` | low and medium traffic; call `prune()` on a schedule |
| `RedisRateLimiter` | atomic `INCR` + `EXPIRE` | concurrent traffic; fails open and logs if Redis is unreachable |

Default limits are 60/minute, 1 000/hour and 10 000/day per address and endpoint. Both backends implement `RateLimiterInterface`, so an existing limiter can be plugged in.

## State API

```php
$state = $shield->middleware();

$state->isIpBlocked('203.0.113.5');
$state->blockIp('203.0.113.5', 'scanner', SecurityMiddleware::SEVERITY_HIGH);
$state->blockPermanently('203.0.113.5', 'manual decision');   // operator only
$state->unblockIp('203.0.113.5');

$state->recordFailedAttempt('203.0.113.5');   // e.g. from your login handler
$state->failedAttempts('203.0.113.5');
$state->clearFailedAttempts('203.0.113.5');

$state->recordIncident('203.0.113.5', 'login_bruteforce', 'Ten failed logins', 'high');
$state->recentIncidentCount('203.0.113.5', 600);
$state->activeBlocks(50);
$state->stats();
$state->cleanup(30);        // retention: expired blocks, old incidents, stale counters
```

When a failed-attempt counter reaches `max_failed_attempts` (25), the next request from that address is blocked once and the counter is cleared.

Tables: `php_shield_ip_blocks`, `php_shield_incidents`, `php_shield_failed_attempts`, `php_shield_rate_limit`, `php_shield_ip_reputation`. All expiries are computed by the database (`NOW()`, `DATE_ADD`), so a PHP/MySQL time-zone difference cannot expire a fresh block.

## Admin dashboard

`public/admin/index.php` — statistics, active blocks, manual block/unblock, masked configuration.

- every state-changing form carries a per-session anti-CSRF token;
- login is rate limited (5 failures → 5 min lockout), the session id is regenerated on login;
- session cookie is `HttpOnly`, `SameSite=Strict`, `Secure` on HTTPS;
- the configuration dump masks passwords, tokens and keys before rendering.

Generate a hash and protect the endpoint at the web-server level too:

```bash
php -r "echo password_hash('your-secret', PASSWORD_DEFAULT), PHP_EOL;"
```

## Reverse proxies and client IP

`X-Forwarded-For` is honoured only when `REMOTE_ADDR` is in `trusted_proxies`, and the chain is read **from right to left**, skipping trusted hops:

```text
X-Forwarded-For: 1.2.3.4, 203.0.113.9      (client-supplied, added by nginx)
REMOTE_ADDR:     10.0.0.5                  (trusted proxy)
→ client = 203.0.113.9
```

Reading the left-most entry instead would let any client choose its own address — and, with a `trusted_ips` entry matching it, bypass the whole shield. This was a real defect, fixed in 2.0.0 and documented in the [security review](docs/security-review.md).

## Architecture

```text
src/
├── ShieldFactory.php              ← wiring from configuration
├── Middleware/
│   ├── Shield.php                 ← decision: inspect() / isRequestAllowed()
│   └── SecurityMiddleware.php     ← state: blocks, incidents, counters, cleanup
├── Detection/                     ← rules + registry
├── ThreatIntel/                   ← AbuseIPDB.com / .ru, cache, circuit breaker
├── Ip/                            ← safe client IP resolution, CIDR
├── RateLimiting/                  ← database + Redis limiters
├── Storage/                       ← block store interfaces + MySQL
├── Admin/                         ← dashboard logic, sessions, CSRF
├── Support/                       ← typed config, redaction, headers
└── Exception/
```

Design decisions, alternatives and their consequences are recorded in [docs/adr.md](docs/adr.md).

## Testing

```bash
composer test          # PHPUnit, 120 tests, no database needed
composer phpstan       # level max, zero errors
composer cs-check      # coding standard

# real MySQL (creates its own tables, never drops a database)
MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test

# live AbuseIPDB check (key from the environment)
ABUSEIPDB_API_KEY=your-key php tools/live-abuseipdb.php 8.8.8.8
```

CI runs PHP 8.1 – 8.5, PHPUnit, PHPStan level max, the coding standard and a syntax check of every PHP file.

## Production checklist

1. Run in `monitor` mode for a few days.
2. Read `php_shield_incidents` and tune `block_threshold` / disable noisy rules.
3. Apply `migrations/schema.sql` and set `auto_migrate` to `false`.
4. Switch the rate limiter to Redis for concurrent traffic.
5. Fill `trusted_proxies` if you are behind a reverse proxy — forwarded headers are honoured **only** from those addresses, and the chain is read right to left.
6. Protect the admin dashboard; set a strong password hash.
7. Schedule `cleanup()` (retention) and `DatabaseRateLimiter::prune()`.
8. Enable `ip_reputation` with AbuseIPDB.com, keep AbuseIPDB.ru as the fallback.
9. Add `SecurityHeaders::send()` early in the request.
10. Switch to `block` mode and watch the 403/429 rate for a day.

## Documentation

- [Wiki](https://github.com/paulmann/PHP-Shield/wiki) — configuration reference, recipes, troubleshooting, upgrade guide
- [Architecture Decision Records](docs/adr.md)
- [Security review](docs/security-review.md) — findings and their fixes
- [Reference adapter](integration/abuseipdb-ru/README.md) — replacing a hand-written AbuseIPDB.RU middleware with this package
- [SECURITY.md](SECURITY.md) — how to report a vulnerability
- [AGENTS.md](AGENTS.md) — instructions for AI coding agents

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first: coding standard, static analysis, tests and the review checklist. Issues and pull requests are welcome; security reports go through [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).

## Credits

Built by Mikhail Deynekin. The severity policy and the state/detection split were shaped by the stand-alone middleware used on AbuseIPDB.RU and by the WAF of PHP-Form-Spam-Checker.

---

**English** · [Русский](README.ru.md) · [Deutsch](README.de.md) · [Español](README.es.md) · [中文](README.zh.md) · [हिन्दी](README.hi.md)
