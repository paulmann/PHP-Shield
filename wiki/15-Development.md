# Development

## Local setup

```bash
git clone https://github.com/paulmann/PHP-Shield.git
cd PHP-Shield
composer install
composer test          # PHPUnit, no services required
composer phpstan       # level max
composer cs-check      # coding standard, dry run
composer cs-fix        # apply it
```

PHP 8.1 – 8.5 are supported; CI runs every version. Locally, one version is enough — but run the suite
on the oldest supported version before a release if you touched type declarations.

## The four gates

| Gate | Command | What it proves |
|---|---|---|
| Unit tests | `composer test` | 120 tests, 273 assertions, no database |
| Static analysis | `composer phpstan` | level max, zero errors, `src` including `Admin` |
| Coding standard | `composer cs-check` | one style, no debates |
| Syntax | `php -l` over every file | nothing broken by a merge |

CI (`.github/workflows/ci.yml`) runs the first three on PHP 8.1, 8.2, 8.3, 8.4 and 8.5, plus
`composer validate --strict` and a syntax check of every PHP file.

## Integration checks

These need services and are run deliberately, not on every commit:

```bash
# real MySQL: creates its own tables in the given database, never drops a database
MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test

# one live reputation lookup (costs quota, prints the raw answer and the parsed value)
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
ABUSEIPDB_RU_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8 --provider=ru
```

`tools/db-selftest.php` covers temporary and permanent blocks, severity lifetimes, incidents, counters,
cleanup, the rate limiter, the reputation cache and the table set — 21 checks.

## Adding a rule, a provider or a store

- **Rule:** a class extending `Detection\AbstractRule` with `getName()`, `getCategory()`, `check()`
  using `$this->match(...)`; register it in `RuleFactory::RULE_MAP`; positive **and** negative tests;
  update the rule table in `README.md` (six language files) and
  [Detection rules](03-Detection-Rules.md).
- **Provider:** `ThreatIntel\ReputationProviderInterface` (`name()`, `lookup()`), `IpReputation` or
  `null`, `ThreatIntelException` when it cannot answer; wire it in `ShieldFactory::buildProviders()`;
  test with a fake transport, never over the network.
- **Store:** `Storage\BlockStoreInterface`; optional capabilities are separate interfaces so a minimal
  store stays small. Compute expiries in SQL, never with `date()`.

## Non-negotiable code rules

1. Never trust a forwarded header you did not append (ADR-003).
2. No automatic permanent bans (ADR-002).
3. Infrastructure failures fail open and are logged (ADR-006).
4. The database owns the clock (ADR-009).
5. Configuration is typed; nonsense raises `ConfigurationException` (F-10).
6. `Shield` decides, `SecurityMiddleware` stores (ADR-005).

## Documentation pipeline

Long-form documentation lives in `wiki/*.md` and is published to the GitHub wiki. The README exists in
six languages and the rule table appears in all of them.

```bash
ghagent wiki build --root .      # wiki/*.md → .ghagent/wiki with a sidebar and a footer
ghagent wiki verify --root .     # links, H1, fences, BOM/CRLF, orphan pages
ghagent wiki publish --root . --push --message "..."
ghagent doc --root .             # markdown lint over the repository
ghagent audit --root .           # repository hygiene score
```

`README.md` is canonical; translations follow it. A change to the quick start or the rule table touches
all six files.

## Release

1. `CHANGELOG.md`: move `Unreleased` entries under the new version with today's date.
2. Bump the version where it appears (badges, `CITATION.cff`).
3. `composer test`, `composer phpstan`, `composer cs-check`, the database self-test.
4. Commit as the owner, tag `vX.Y.Z`, push the tag.
5. Create the GitHub release with the section from `CHANGELOG.md` as its body.

## Pull requests

- Describe the motivation and any false-positive considerations.
- A rule without a negative test is rejected.
- Update `CHANGELOG.md` in the same commit; update `README.md` and the wiki when the public API or
  configuration changes.
- Never commit a secret, a real customer address or a production host name.
