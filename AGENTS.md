# AGENTS.md — instructions for AI coding agents

How to install, test and extend **PHP Shield** (formerly shipped under the working name
*SecurityMiddleware*). Read this before changing anything; the long-form reference is the
[wiki](https://github.com/paulmann/PHP-Shield/wiki), the source of the pages is `wiki/`.

## Project at a glance

- Composer package `paulmann/php-shield`, namespace `Deynekin\PhpShield\`
- Entry point `Deynekin\PhpShield\Middleware\Shield`, built by `Deynekin\PhpShield\ShieldFactory`
- PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`; optional `ext-mysqli`, `ext-redis`, `ext-curl`

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

`inspect()` returns `blocked`, `status`, `reason`, `detail`, `score`, `findings`;
`isRequestAllowed()` is the boolean facade.

## Five rules that are not negotiable

| # | Rule | Why it exists | Regression guard |
|---|---|---|---|
| 1 | Never trust a forwarded header you did not append: read `X-Forwarded-For` right to left, only from `trusted_proxies` | reading it left to right let a client pick its own address and bypass the shield | `IpResolverTest` |
| 2 | No automatic permanent bans. Scores accumulate; a permanent block is an operator action | one regex must never lock a customer out forever | `ShieldTest` |
| 3 | Infrastructure failures fail open: storage and reputation errors are logged, never thrown into the request path | an outage means "no data", not "deny" (ADR-006) | `ShieldTest`, `ReputationCheckerTest` |
| 4 | The database owns the clock: no `date()` in a column compared with `NOW()` | a time-zone mismatch made fresh blocks expire instantly (ADR-009) | `tools/db-selftest.php` |
| 5 | Configuration is typed through `Support\Config`; an unknown mode or rule must raise `ConfigurationException` | silent fallback disables protection | `ConfigTest` |

`Middleware\Shield` owns the verdict (rate limits, scanning, reputation) and must not write to
storage; `Middleware\SecurityMiddleware` owns state (blocks, incidents, counters) and must not
detect. That split is ADR-005 — do not blur it.

## Adding a detection rule

1. New class in `src/Detection/` extending `AbstractRule`.
2. Implement `getName()`, `getCategory()`, `check()`; use `$this->match($pattern, $value, $field, $score, $description)`.
3. Register it in `RuleFactory::RULE_MAP`, or document `RuleFactory::register()` for project rules.
4. Add the name to `enabled_rules` in `config/default.php` only if it is safe by default.
5. Add **positive and negative** tests — a rule without a negative case is rejected.
6. Update the rule table in `README.md` (all six language files) and `wiki/03-Detection-Rules.md`.
7. Keep patterns conservative: a false positive in a security library is a customer outage.

## Adding a reputation provider or a storage backend

- Provider: implement `ThreatIntel\ReputationProviderInterface` (`name()`, `lookup()`), return an
  `IpReputation` or `null`, throw `ThreatIntelException` when the provider cannot answer; wire it in
  `ShieldFactory::buildProviders()` and test it with a fake transport, never over the network.
- Storage: implement `Storage\BlockStoreInterface`. Optional capabilities are separate interfaces —
  `FailedAttemptStoreInterface`, `MaintenanceStoreInterface` — so a minimal store stays small.

## Testing expectations

```bash
composer test        # PHPUnit, no services required (120 tests)
composer phpstan     # level max, must be 0 errors
composer cs-check    # coding standard

MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
```

All four must pass before a change is proposed. The database self-test creates its own tables in the
given database and never drops a database. CI runs PHP 8.1 – 8.5, PHPUnit, PHPStan and the coding
standard.

## File map

| Path | Purpose |
|---|---|
| `src/ShieldFactory.php` | wiring from configuration |
| `src/Middleware/Shield.php` | decision engine (`inspect`) |
| `src/Middleware/SecurityMiddleware.php` | state: blocks, incidents, counters, cleanup, stats |
| `src/Detection/`, `src/ThreatIntel/` | rules and `RuleFactory`; AbuseIPDB.com/.ru client, cache, breaker |
| `src/Ip/`, `src/RateLimiting/`, `src/Storage/` | client IP and CIDR; database and Redis limiters; block stores |
| `src/Admin/`, `public/admin/index.php` | dashboard logic, sessions, CSRF; the dashboard itself |
| `src/Support/` | typed config, redaction, security headers |
| `config/default.php`, `migrations/schema.sql` | annotated defaults; production schema |
| `wiki/` | documentation sources — the published wiki is generated from here |

## Documentation debts

- `README.md` is canonical and translated into `README.ru.md`, `README.de.md`, `README.es.md`,
  `README.zh.md`, `README.hi.md`; a change to the rule table or the quick start touches all six.
- Long-form docs live in `wiki/*.md`; after editing, run `ghagent wiki build --root .` and
  `ghagent wiki verify --root .`, then publish.
- `CHANGELOG.md` keeps a Keep a Changelog structure with an `Unreleased` section. Update it in the
  same commit as the code.
- Never commit an API key, a password hash or a real customer address; configuration examples read
  keys from environment variables.
