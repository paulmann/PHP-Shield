# Security review — PHP Shield 2.0.0

Scope: every PHP file in `src/`, `public/admin/`, `config/default.php`, `migrations/schema.sql`.
Method: manual review, static analysis at PHPStan level max, unit tests (no services), a database
integration test against MySQL 9.7.2 and a live AbuseIPDB check.

Baseline before the review: PHPUnit 22 tests green, **PHPStan level max reported 50 errors** (the CI
`phpstan` job was therefore red), `composer cs-check` aborted because the fixer config used a risky
rule without `setRiskyAllowed(true)`.

## Findings

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| F-01 | High | `Ip/IpResolver` | `X-Forwarded-For` was read from the **left**, so a client could choose its own address; combined with any `trusted_ips` entry this bypassed every check (trusted addresses return early) | Fixed |
| F-02 | High | `public/admin`, `Admin/AdminDashboard` | No CSRF token on block/unblock/logout; login had no throttle; session id was not regenerated on login; cookies lacked `SameSite`/`HttpOnly` | Fixed |
| F-03 | High | `public/admin` | The dashboard rendered the whole configuration, including `admin.password_hash` and `redis.password` | Fixed |
| F-04 | Medium | `Storage/MysqlBlockStore` | `json_encode(..., JSON_THROW_ON_ERROR)` on attacker-controlled context: one invalid UTF-8 byte raised `JsonException` while handling a threat, turning detection into a 500 | Fixed |
| F-05 | Medium | `RateLimiting/DatabaseRateLimiter` | `get_result()` result was used unchecked: `fetch_assoc()` on `false` is a fatal error whenever the statement failed | Fixed |
| F-06 | Medium | `MysqlBlockStore`, `DatabaseRateLimiter` | `CREATE TABLE IF NOT EXISTS` ran on **every request** (constructor) — DDL latency and CREATE privileges at runtime | Fixed (`auto_migrate`, default off in production) |
| F-07 | Medium | whole library | Percent-encoded payloads (`%3Cscript%3E`) were not decoded before matching, and `REQUEST_URI` was never scanned | Fixed |
| F-08 | Medium | `config/default.php` | Default mode was `block` while the docs demand "start in monitor"; default `trusted_ips` included every private range, silently exempting whole networks | Fixed |
| F-09 | Medium | `Middleware/SecurityMiddleware` | A rate-limit breach blocked the address for `block_duration` (1 h) — self-inflicted DoS for anyone behind shared NAT | Fixed (`rate_limit_block_duration`, 300 s) |
| F-10 | Medium | config handling | An unknown `mode` (e.g. `blocks`) silently disabled blocking; wrong types were cast blindly | Fixed (`Support\Config` throws) |
| F-11 | Low | `Storage/MysqlBlockStore` | `expires_at` was written with PHP's clock but compared with MySQL's `NOW()`; when the processes sit in different time zones a fresh block expired immediately (reproduced on MySQL 9.7.2) | Fixed (database clock) |
| F-12 | Low | `support/SecurityHeaders` | No validation of header names/values — a CRLF in a value is a response-splitting hazard | Fixed |
| F-13 | Low | `Support/PayloadRedactor` | Unbounded recursion; objects were passed through untouched | Fixed (depth limit, objects replaced) |
| F-14 | Low | `Detection/CommandInjectionRule` | The backtick pattern matched any `` `text` `` in prose (false positives on documentation) | Fixed (command name required) |
| F-15 | Low | `migrations/schema.sql` | Drifted from the runtime DDL: `INT` vs `BIGINT UNSIGNED`, `VARCHAR(50)` vs `64`, different index names | Fixed |
| F-16 | Low | `phpstan.neon` | `src/Admin` was excluded from analysis — the file with the most logic was the least checked | Fixed |
| F-17 | Info | `public/admin` | `header('Location: ' . $_SERVER['PHP_SELF'])` (attacker-influenced) and `@new mysqli` (which throws, not returns, on PHP ≥ 8.1) | Fixed |

## Verification performed

| Check | Command | Result |
|---|---|---|
| Unit tests | `composer test` | 120 tests, 273 assertions, green |
| Static analysis | `composer phpstan` (level max, `src` incl. `Admin`) | 0 errors |
| Coding standard | `composer cs-check` | clean |
| Syntax | `php -l` over `src`, `tests`, `config`, `examples`, `public`, `tools` | 0 errors |
| Database | `php -d extension=mysqli tools/db-selftest.php php_shield_test` on MySQL 9.7.2 | 21 checks passed (blocks, severities, incidents, counters, cleanup, rate limiter, reputation cache, table set) |
| Live AbuseIPDB.com | `php tools/live-abuseipdb.php 8.8.8.8` | `score=0 whitelisted=yes isp=Google LLC` |
| Live AbuseIPDB.com | `php tools/live-abuseipdb.php 118.25.6.39` | `score=0 reports=2 country=CN isp=Tencent Cloud` |
| AbuseIPDB.ru | contract tests against real response samples | parser, URL, `Key:` header, 401/422/429 all covered; **the live host does not answer (TLS handshake fails) as of 2026-11-07** |

## Regression coverage added

- `IpResolverTest` — spoofed left-most entry, multi-hop chains, invalid hops, non-IP `REMOTE_ADDR`.
- `ShieldTest` — blocked/trusted/monitor/challenge flows, URI scanning, encoded payloads, deduplication, failed-attempt escalation, reputation block/flag/whitelist/outage.
- `SecurityMiddlewareTest` — severity lifetimes, explicit TTL, permanent blocks, trusted addresses, counters, cleanup.
- `AbuseIpDbProviderTest`, `ReputationCheckerTest` — envelope parsing, base URL and header, private-address short circuit, cache, provider fallback, breaker, quota window.
- `AdminDashboardTest` — authentication, lockout, CSRF rotation, masked configuration.
- `ConfigTest`, `SecurityHeadersTest`, `PayloadRedactorTest`, `DetectionRulesTest` — validation, header injection, depth limits, positive/negative rule cases.

## Residual risks and open items

1. **Signature detection is not a WAF.** Obfuscated payloads that stay syntactically legal will pass. Use prepared statements and output encoding first.
2. **Reputation is advisory.** A score below `block_score` never blocks by design; a compromised AbuseIPDB entry cannot lock a visitor out below the threshold.
3. **Fail-open is a deliberate trade-off** (ADR-006). During a database outage no new block is recorded.
4. **AbuseIPDB.ru is untested live** — the host was unreachable; only the contract (fixtures, header, URL, error codes) is verified. Re-run `tools/live-abuseipdb.php --provider=ru` once the service is up.
5. **Redis failure returns "allowed"** — documented, configurable only by implementing `RateLimiterInterface`.
6. **`DatabaseRateLimiter` is not atomic** (count-then-insert). For strict limits use Redis; the overshoot equals the number of in-flight requests.
