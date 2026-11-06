# Contributing to PHP Shield

Thanks for taking the time to improve PHP Shield.

## Development setup

```bash
git clone https://github.com/paulmann/PHP-Shield.git
cd PHP-Shield
composer install
composer test
composer phpstan
composer cs-check
```

With services (optional but recommended before a release):

```bash
MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test
ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php 8.8.8.8
```

## Ground rules

1. **Detect on the server, never trust a header you did not append.** `X-Forwarded-For` is read right
   to left and only from `trusted_proxies`.
2. **No automatic permanent bans.** Scores accumulate; permanent blocks are an operator action.
3. **Fail open on infrastructure trouble.** Database, Redis and reputation failures are logged, never
   turned into a denial.
4. **The database owns the clock.** No `date()` in a column compared with `NOW()`.
5. **Configuration is typed.** Read it through `Support\Config`; raise `ConfigurationException` on
   nonsense instead of ignoring it.

## Adding a detection rule

1. New class in `src/Detection/` extending `AbstractRule`.
2. Implement `getName()`, `getCategory()`, `check()`.
3. Register it in `RuleFactory::RULE_MAP` (or use `RuleFactory::register()` from a project).
4. Add **positive and negative** tests.
5. Document it in the README and wiki rule tables.

Keep patterns conservative: a false positive in a security library is a customer outage.

## Pull requests

- Describe the motivation and any false-positive considerations.
- Include tests; a rule without a negative case will be rejected.
- Update `CHANGELOG.md` and, if the public API changed, `README.md` plus `docs/wiki.md`.
- Make sure `composer test`, `composer phpstan` and `composer cs-check` are green.
- Never commit secrets, real customer addresses or production host names.

## Reporting security issues

Report privately to **Mikhail@Deynekin.com** — see [SECURITY.md](SECURITY.md). Do not open a public
issue for a vulnerability.
