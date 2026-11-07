# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- README in six languages — English, Russian, German, Spanish, Chinese and Hindi — with a language switcher on every file.
- A wiki under `wiki/`: sixteen pages covering configuration, detection, reputation, storage, rate limiting, the dashboard, reverse proxies, deployment, troubleshooting and the upgrade path. Built and published with `ghagent wiki`.
- Repository hygiene: `.gitattributes`, `.editorconfig`, issue forms, a pull-request template, `CODEOWNERS`, Dependabot, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`.
- A social preview rendered by `ghagent assets` (`assets/social-preview.png` and `.svg`).
- A request-flow diagram in Mermaid, translated into all six README files and repeated on the wiki home and architecture pages: the order of the checks, the branch of each layer and the decision array every branch returns.

### Changed

- `docs/wiki.md` is now a map of the documentation instead of a second copy of it; the wiki is the single long-form source.
- Vulnerability reports go through GitHub private reporting; the personal e-mail address was removed from `SECURITY.md` and `CONTRIBUTING.md`.
- `AGENTS.md` points at the wiki and the shared rule map instead of repeating the reference tables.

## [2.1.0] - 2026-11-08

### Added

- **Asynchronous reputation by default.** The request path no longer calls AbuseIPDB: a known address
  is answered from the cache, an unknown one is queued (`php_shield_reputation_queue`) and the worker
  fills the cache out of band. `ip_reputation.mode` switches back to `sync` at any time.
- `tools/reputation-worker.php` — cron entry point with `--status`, `--ip=<address>` and `--limit=N`.
- `ThreatIntel\ReputationQueueInterface` with `MysqlReputationQueue` and `ArrayReputationQueue`,
  `ThreatIntel\ReputationWorker` with `per_run` quota guard and `retry_after` backoff,
  `ReputationChecker::fetchOrThrow()` for the worker and `queueSize()` for monitoring.
- `ShieldFactory::createReputationWorker()`; `ip_reputation.queue_batch` / `per_run` / `retry_after`.
- New table `php_shield_reputation_queue`; `migrations/schema.sql` updated.
- Tests: 134 (queue deduplication, drain, backoff, quota budget, async request path, sync switch);
  the database self-test now covers the queue against real MySQL (28 checks).
- ADR-010 documenting the async decision and the alternatives that were rejected.

### Changed

- `ReputationChecker::lookup()` is cache-only in async mode; the network call moved to `fetch()` /
  `fetchOrThrow()`. Manual construction stays synchronous, `ShieldFactory` enables async from config.
- The worker keeps a failed address queued instead of dropping it, so a provider outage retries later.

## [2.0.0] - 2026-11-07

The rebranded release: the project formerly shipped as *SecurityMiddleware* is now **PHP Shield**.

### Added

- **IP reputation via AbuseIPDB** — one client for both communities, because abuseipdb.com and abuseipdb.ru share the API v2 contract: `ThreatIntel\AbuseIpDbProvider` with `com()` / `ru()` constructors, `ReputationChecker` with provider fallback, shared cache, quota window and circuit breaker, `IpReputation` value object.
- `Middleware\Shield` — the decision entry point. `inspect()` returns a decision array (`blocked`, `status`, `reason`, `detail`, `score`, `findings`); `isRequestAllowed()` remains as a boolean facade.
- Severity-based block lifetimes (`severity_block_multipliers`): low 30 min, medium 1 h, high 4 h, critical 12 h.
- Failed-attempt counters with escalation (`max_failed_attempts`, default 25) and `Storage\FailedAttemptStoreInterface`.
- Retention cleanup (`SecurityMiddleware::cleanup()`, `Storage\MaintenanceStoreInterface`) and richer statistics (by type, top addresses).
- `Support\Config` — typed, validating configuration access; unknown mode or rule names now fail loudly.
- `Support\SecurityHeaders::build()` for testing header sets without emitting them.
- Anti-CSRF tokens, login lockout, session regeneration and cookie hardening in the admin dashboard; the configuration dump is masked.
- `tools/db-selftest.php` (real MySQL integration test) and `tools/live-abuseipdb.php` (live reputation check).
- `integration/abuseipdb-ru/` — reference adapter that replaces the hand-written middleware of the AbuseIPDB.RU platform with this package, plus its end-to-end test (verified: site smoke 7/7, adapter 15/15).
- `SECURITY.md`, `docs/security-review.md`.

### Changed

- `ShieldFactory::create()` returns `Shield`; `createWithComponents()` needs no MySQL at all.
- `SecurityMiddleware` now owns state only: blocks, incident journal, counters, cleanup, statistics.
- Default `mode` is `monitor`; default `trusted_ips` is loopback only (an allowlist entry bypasses every check).
- Default `rate_limit_block_duration` is 300 s, so a burst cannot lock out a shared address for an hour.
- Detection values are also scanned after URL decoding, `stripslashes` and NUL removal; `REQUEST_URI` is scanned.
- Block expiries are computed by the database (`NOW()`, `DATE_ADD`), removing a PHP/MySQL time-zone dependency.
- CI matrix extended to PHP 8.5; the coding-standard step is mandatory again.
- `ext-curl` documented as the transport for reputation lookups.
- **Breaking:** `BlockStoreInterface::block()` takes a `$severity` argument; `countIncidents()` and `getRecentIncidents()` are required.
- **Breaking:** `SecurityMiddleware::isRequestAllowed()` moved to `Shield`.
- **Breaking:** the `composer.json` package name is `paulmann/php-shield`.

### Fixed

- **Client IP spoofing**: `X-Forwarded-For` was read from the left, so a client behind a trusted proxy could pick its own address and, matching a `trusted_ips` entry, bypass the whole shield. The chain is now read right to left.
- **Fatal error on binary payloads**: `json_encode(..., JSON_THROW_ON_ERROR)` in incident logging turned one invalid UTF-8 byte into a `JsonException` during threat handling. Invalid bytes are now substituted.
- **Unchecked `mysqli_result`**: `DatabaseRateLimiter` called `fetch_assoc()` on `false`, a fatal error whenever the statement failed.
- **Interactive SQL injection surface in the dashboard**: configuration (including password hash and Redis password) was rendered in full; it is now redacted.
- **CSRF**: block/unblock/logout accepted cross-site POSTs.
- **PHPStan level max did not pass** (50 errors); the CI job is green now and analyses `src/Admin` again.
- **`composer cs-check` always failed** — the config used a risky fixer without `setRiskyAllowed(true)`.
- **Schema drift**: `migrations/schema.sql` disagreed with the runtime DDL (`INT` vs `BIGINT UNSIGNED`, `VARCHAR(50)` vs `64`, index names).
- Command-injection backticks matched any `` `text` `` in prose; they now require a command name.

## [1.1.0] - 2026-11-07

### Added

- `RedisRateLimiter`, `ShieldFactory`, `RuleFactory`, exception hierarchy.
- Unit tests for CIDR, IP resolver, detection rules, redaction and the rule registry.
- GitHub Actions CI (PHP 8.1–8.4, PHPUnit, PHPStan), `phpstan.neon` at level max.
- Admin dashboard statistics and manual block form, `AGENTS.md`.

### Changed

- `BlockStoreInterface` includes `getStats()`; `MysqlBlockStore` gained richer statistics.
- `CidrMatcher` rewritten on a single binary comparison for IPv4 and IPv6.
- `IpResolver` normalises IPv6 zone identifiers.

## [1.0.0] - 2026-11-07

### Added

- Initial modular release: detection rules, score-based blocking, modes, safe IP resolution, admin dashboard, payload redaction.

[Unreleased]: https://github.com/paulmann/PHP-Shield/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/paulmann/PHP-Shield/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/paulmann/PHP-Shield/releases/tag/v2.0.0
[1.1.0]: https://github.com/paulmann/PHP-Shield/releases
[1.0.0]: https://github.com/paulmann/PHP-Shield/releases
