# Architecture Decision Records (ADR)

## ADR-001: Modular Detection Rules

**Status**: Accepted

**Context**: The original middleware kept a large array of regular expressions inside one class, which made it hard to test and impossible to enable selectively.

**Decision**: Each detection category is a separate class implementing `RuleInterface`, created through `RuleFactory`.

**Consequences**: rules are unit-testable in isolation, configuration controls which ones load, and `RuleFactory::register()` lets a project add a rule without forking.

## ADR-002: Score-based Blocking Instead of Immediate Permanent Ban

**Status**: Accepted

**Context**: Banning on any signature match turned every false positive into a denial of service against a real visitor.

**Decision**: Rules return scores; scores accumulate; only a total above `block_threshold` blocks. Permanent blocks are an explicit operator action (`blockPermanently()` or the dashboard).

**Consequences**: sensitivity is tunable per application, high-confidence attacks still block immediately, and no regex can ban a customer forever.

## ADR-003: Trusted Proxy Model for Client IP

**Status**: Accepted

**Context**: Blindly trusting `X-Forwarded-For` lets a client choose its own address.

**Decision**: Forwarded headers are honoured only when `REMOTE_ADDR` is in `trusted_proxies`, and the chain is walked **right to left**, skipping trusted hops. The left-most entry is never trusted unless every hop was one of our own proxies.

**Consequences**: correct behaviour behind nginx/ALB, no spoofing, and `trusted_ips` can no longer be reached by a header. Regression covered by `IpResolverTest::testIgnoresSpoofedLeftmostForwardedEntry`.

## ADR-004: Storage and Rate-Limiting Interfaces

**Status**: Accepted

**Decision**: `BlockStoreInterface` and `RateLimiterInterface` are the only storage contracts. MySQL is one implementation; SQLite, PostgreSQL or in-memory stores plug in without touching the decision layer.

**Consequences**: `ShieldFactory::createWithComponents()` needs neither MySQL nor Redis, which also makes the tests independent of services.

## ADR-005: Detection and State Are Separate Classes

**Status**: Accepted

**Context**: A single class that both detects and stores grows into a monolith, and every new detection rule risks breaking block bookkeeping.

**Decision**: `Middleware\Shield` decides (`inspect()` → decision array). `Middleware\SecurityMiddleware` owns state (blocks, incident journal, counters, cleanup, statistics). The shield calls the state object; the state object never scans.

**Consequences**: one source of truth for detection and one for state; the state API can be used from a login handler or a CLI tool without pulling the detection rules in; the split matches the middleware already running on AbuseIPDB.RU, which keeps the two implementations comparable.

## ADR-006: Infrastructure Failures Are Fail-Open

**Status**: Accepted

**Context**: This library runs inside someone else's request path. A database hiccup or an AbuseIPDB outage must not become a total outage of the site.

**Decision**: Every storage call catches `mysqli_sql_exception` and logs it, returning "not blocked"/"no statistics". The reputation layer treats any failure as "no data". A reputation answer that is missing never blocks.

**Consequences**: during an outage the local rules keep working and stops lose state; the alternative (fail closed) turns a shared-hosting incident into a 500 for every visitor. Operators who need fail-closed can implement their own `BlockStoreInterface`.

## ADR-007: One Client for Two AbuseIPDB Communities

**Status**: Accepted

**Context**: abuseipdb.com and abuseipdb.ru implement the same API v2 contract — same paths, same `Key:` header, same envelopes — and the Russian service is a drop-in replacement for the international one.

**Decision**: A single `AbuseIpDbProvider` parameterised by base URL, plus `ReputationChecker` holding an ordered list of providers. The first provider that answers wins; the next one is tried on failure.

**Consequences**: a project can run against `.ru` only, `.com` only, or both (`.com` first, `.ru` as fallback). The compatibility itself is enforced by `AbuseIpDbProviderTest`, which asserts URL, header and envelope parsing against real sample responses.

## ADR-008: Quotas, Cache and Circuit Breaker in Front of the API

**Status**: Accepted

**Context**: `/check` is rate limited, and a reputation call inside a request is the most expensive thing the library does.

**Decision**: answers are cached (`cache_ttl`, shared through `php_shield_ip_reputation`); private and reserved addresses are never queried; `429` opens the advertised retry window and is never retried in-process; after `circuit_breaker.failures` consecutive errors the provider is skipped for `cooldown` seconds.

**Consequences**: a burst costs one query, a broken provider costs nothing, and the shield keeps its latency budget (2 s timeout by default).

## ADR-010: Reputation Is Asynchronous by Default

**Status**: Accepted

**Context**: `/check` is an external HTTP call. Even with a 2-second timeout and a cache, calling it inline
puts a third-party service inside the request path: a slow provider, a DNS hiccup or a quota window
becomes latency for a visitor, and on a busy site it becomes a queue of blocked PHP workers.

**Decision**: `ip_reputation.mode = 'async'` by default. `ReputationChecker::lookup()` answers from the
cache and, on a miss, only enqueues the address (`php_shield_reputation_queue`, one `INSERT ... ON
DUPLICATE KEY UPDATE`). A cron worker (`tools/reputation-worker.php`) drains the queue, respects
`per_run`, stores the answer in `php_shield_ip_reputation` and retries failures with `retry_after`
backoff. `'sync'` remains available and performs the call inline.

**Consequences**: no request ever waits for AbuseIPDB, and the reputation verdict for a brand-new address
applies from the next request instead of the current one. That is acceptable because reputation is an
*addition* to the local rules: the first request is still inspected and rate limited by them. The
worker's failure mode is benign — if it does not run, the queue grows and the shield keeps working.

**Alternatives rejected**: (a) blocking call with a short timeout — still a third-party dependency in
the request path; (b) fire-and-forget from PHP-FPM after `fastcgi_finish_request()` — not portable to
CLI/other SAPIs and loses the request when the worker dies; (c) an in-process queue — nothing survives
the request that filled it.

## ADR-009: Time Comes From the Database

**Status**: Accepted

**Context**: A real integration test on MySQL 9.7 showed a fresh 60-second block expiring immediately: PHP wrote `expires_at` from `date()` while the query compared it with `NOW()`, and the two processes sat in different time zones.

**Decision**: every expiry and every cutoff is computed inside SQL — `DATE_ADD(NOW(), INTERVAL ? SECOND)`, `DATE_SUB(NOW(), INTERVAL ? DAY)`, `expires_at > NOW()` — and `FROM_UNIXTIME(?)` is used where a PHP timestamp must be compared with a stored `DATETIME`.

**Consequences**: the library is time-zone agnostic. Writing `date()` into a column that is later compared with `NOW()` is forbidden in this codebase; the DB self-test covers both a temporary and a permanent block.
