# Security

## What the library promises

- Trusted addresses are never blocked and never counted.
- A single detection never produces a permanent ban.
- Infrastructure failures (database, Redis, reputation API) never block a visitor; they are logged.
- Secrets are never written to logs or rendered by the dashboard.

These are the invariants to test a change against. `ShieldTest`, `SecurityMiddlewareTest` and
`AdminDashboardTest` encode them.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private reporting for this repository
(<https://github.com/paulmann/PHP-Shield/security/advisories/new>) and include:

- affected version, a reproduction (request payload or configuration), observed and expected behaviour,
  and whether the issue is remotely exploitable;
- an initial answer arrives within three working days.

Please allow a reasonable window to ship a fix before publishing details. Credit is given in
`CHANGELOG.md` unless you prefer to stay anonymous. Full policy:
[SECURITY.md](https://github.com/paulmann/PHP-Shield/blob/main/SECURITY.md).

## The 2.0.0 review in one table

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | High | `X-Forwarded-For` was read from the left: a client could choose its own address and, matching `trusted_ips`, bypass every check | Fixed |
| F-02 | High | dashboard: no CSRF token on block/unblock/logout, no login throttle, session id not regenerated, cookies without `SameSite`/`HttpOnly` | Fixed |
| F-03 | High | the dashboard rendered the whole configuration, including the password hash and the Redis password | Fixed |
| F-04 | Medium | `json_encode(..., JSON_THROW_ON_ERROR)` on attacker-controlled context: one invalid UTF-8 byte raised an exception inside threat handling | Fixed |
| F-05 | Medium | `mysqli_result` used unchecked — `fetch_assoc()` on `false` was a fatal error | Fixed |
| F-06 | Medium | `CREATE TABLE IF NOT EXISTS` ran on every request (constructor DDL) | Fixed (`auto_migrate`, production default off) |
| F-07 | Medium | percent-encoded payloads were not decoded before matching; `REQUEST_URI` was never scanned | Fixed |
| F-08 | Medium | default mode was `block`; default `trusted_ips` exempted all private ranges | Fixed |
| F-09 | Medium | a rate-limit breach blocked for an hour, self-inflicted DoS behind NAT | Fixed (300 s) |
| F-10 | Medium | an unknown `mode` silently disabled blocking; types were cast blindly | Fixed (`Support\Config` throws) |
| F-11 | Low | block expiry used PHP's clock but was compared with MySQL's `NOW()` — fresh blocks expired immediately | Fixed (database clock) |
| F-12 | Low | no validation of header names/values in `SecurityHeaders` (response splitting) | Fixed |
| F-13 | Low | unbounded recursion in `PayloadRedactor` | Fixed |
| F-14 | Low | the backtick pattern matched any inline code in prose | Fixed |
| F-15 | Low | `migrations/schema.sql` drifted from the runtime DDL | Fixed |
| F-16 | Low | `src/Admin` was excluded from PHPStan — the file with the most logic was the least checked | Fixed |
| F-17 | Info | `PHP_SELF` in a `Location` header; `@new mysqli`, which throws rather than returning on PHP ≥ 8.1 | Fixed |

All seventeen are closed and each fixed defect has a regression test. The full review, with the
verification table and the live measurements, is
[docs/security-review.md](https://github.com/paulmann/PHP-Shield/blob/main/docs/security-review.md).

## Residual risks — read these before deploying

1. **Signature detection is not a WAF.** Obfuscated but syntactically legal payloads pass. Prepared
   statements and output encoding come first; this library is the layer that notices the noise.
2. **Reputation is advisory.** Below `block_score` nothing blocks, by design — a bad entry in a
   third-party database cannot lock a visitor out.
3. **Fail-open is a trade-off** (ADR-006). During a database outage no new block is recorded, so an
   attack that starts during the outage is not remembered.
4. **AbuseIPDB.ru is verified by contract, not live.** The host did not answer on 2026-11-07; the
   parser, the URL, the `Key:` header and the 401/422/429 handling are covered by fixtures. Re-run
   `tools/live-abuseipdb.php <ip> --provider=ru` once the service is reachable.
5. **Redis failure returns "allowed".** Documented; to change it, implement `RateLimiterInterface`.
6. **`DatabaseRateLimiter` is not atomic** (count, then insert). The overshoot equals the number of
   in-flight requests; use Redis where precision matters.

## Hardening a deployment

The [production checklist](10-Production-Checklist.md) is the operational version of this page. The
three items that matter most:

- keep `trusted_ips` and `trusted_proxies` minimal, and verify with a forged header;
- keep keys in the environment, never in the tree — and never in the dashboard configuration file;
- put the dashboard behind the web server's own access control, not only behind its password.
