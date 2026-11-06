# AGENTS.md — instructions for AI coding agents

This file explains how to install, configure, test and extend **PHP Shield** (formerly shipped under the
working name *SecurityMiddleware*). Read it before changing anything.

## Project overview

- Composer package: `paulmann/php-shield`
- Namespace: `Deynekin\PhpShield\`
- Repository: <https://github.com/paulmann/PHP-Shield>
- Entry point: `Deynekin\PhpShield\Middleware\Shield` (built by `Deynekin\PhpShield\ShieldFactory`)
- Requires PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`

## Install and run

```bash
composer require paulmann/php-shield
```

```php
use Deynekin\PhpShield\ShieldFactory;

$config = require 'vendor/paulmann/php-shield/config/default.php';
$config['mode'] = 'monitor';                       // always start here

$shield = ShieldFactory::create($config, new mysqli($host, $user, $pass, $db));

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');

if ($decision['blocked']) {
    http_response_code($decision['status']);
    exit;
}
```

`inspect()` returns `blocked`, `status`, `reason`, `detail`, `score`, `findings`.
`isRequestAllowed()` is the boolean facade.

## Two classes, two jobs — keep them apart

| Class | Owns | Must not |
|---|---|---|
| `Middleware\Shield` | rate limits, payload/header scanning, reputation, the verdict | write to storage directly |
| `Middleware\SecurityMiddleware` | blocks, incident journal, failed-attempt counters, cleanup, statistics | detect anything |

The shield calls `recordIncident()` / `blockIp()`; the state class never scans. See `docs/adr.md` ADR-005.

## Rule 1 — never trust a forwarded header you did not append

`IpResolver` reads `X-Forwarded-For` **right to left** and only when `REMOTE_ADDR` is in
`trusted_proxies`. Never change this to "first IP wins": the left-most entry is client-supplied and a
matching `trusted_ips` entry would bypass every check (regression: `IpResolverTest`).

## Rule 2 — no automatic permanent bans

Scores accumulate and only a total above `block_threshold` blocks, for a severity-derived lifetime.
Permanent blocks come from an explicit operator action (`blockPermanently()`, the dashboard).

## Rule 3 — infrastructure failures fail open

Storage and reputation errors are logged, never thrown into the request path: an outage means "no
data", not "deny" (ADR-006). Do not add a `throw` to a hot path.

## Rule 4 — the database owns the clock

Never write `date()` into a column that is later compared with `NOW()`. Use
`DATE_ADD(NOW(), INTERVAL ? SECOND)`, `DATE_SUB(NOW(), INTERVAL ? DAY)`, `FROM_UNIXTIME(?)`.
A real time-zone mismatch made fresh blocks expire instantly (ADR-009, covered by `tools/db-selftest.php`).

## Rule 5 — configuration is typed

Read configuration through `Support\Config` (`string`, `int`, `bool`, `stringList`, `map`,
`nestedInt`, `mode`, `rateLimits`). Never cast blindly: an unknown mode must raise
`ConfigurationException`, not silently disable blocking.

## Adding a detection rule

1. New class in `src/Detection/` extending `AbstractRule`.
2. Implement `getName()`, `getCategory()`, `check()`; use `$this->match($pattern, $value, $field, $score, $description)`.
3. Register it in `RuleFactory::RULE_MAP` (core rules) or document `RuleFactory::register()` (project rules).
4. Add the name to `enabled_rules` in `config/default.php` only if it is safe by default.
5. Add **positive and negative** test cases — a rule without a negative case is not accepted.
6. Update the rule table in `README.md` and `docs/wiki.md`.
7. Keep patterns conservative: false positives are worse than false negatives for a library.

## Adding a reputation provider

Implement `ThreatIntel\ReputationProviderInterface` (`name()`, `lookup()`), return an `IpReputation`
or `null`, throw `ThreatIntelException` when the provider cannot answer. Add it to
`ShieldFactory::buildProviders()` and cover it with a fake transport; never call the network in tests.

## Adding a storage backend

Implement `Storage\BlockStoreInterface`. Optional capabilities are separate interfaces, so a minimal
store stays small: `FailedAttemptStoreInterface`, `MaintenanceStoreInterface`.

## Testing expectations

```bash
composer install
composer test        # PHPUnit, no services required
composer phpstan     # level max, must be 0 errors
composer cs-check    # coding standard

MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
```

All four must pass before a change is proposed. The database self-test creates its own tables in the
given database and never drops a database.

## File map

| Path | Purpose |
|---|---|
| `src/ShieldFactory.php` | wiring from configuration |
| `src/Middleware/Shield.php` | decision engine (`inspect`) |
| `src/Middleware/SecurityMiddleware.php` | state: blocks, incidents, counters, cleanup, stats |
| `src/Detection/` | rules and `RuleFactory` |
| `src/ThreatIntel/` | AbuseIPDB.com / AbuseIPDB.ru client, cache, circuit breaker |
| `src/Ip/` | client IP resolution and CIDR matching |
| `src/RateLimiting/` | database and Redis limiters |
| `src/Storage/` | block store contracts and the MySQL implementation |
| `src/Admin/` | dashboard logic, sessions, CSRF |
| `src/Support/` | typed config, redaction, security headers |
| `public/admin/index.php` | web dashboard |
| `config/default.php` | annotated configuration |
| `migrations/schema.sql` | production schema |
| `docs/wiki.md`, `docs/adr.md`, `docs/security-review.md` | documentation |

## Pull requests

- Update `CHANGELOG.md` (Keep a Changelog sections, newest first).
- Update `README.md` and `docs/wiki.md` when the public API or configuration changes.
- Add tests; keep PHPStan level max happy.
- Never commit an API key, a password hash or a real customer address. Configuration examples use
  environment variables.
