# Architecture

## Four layers, two classes with a job each

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

| Layer | Class | Owns | Must not |
|---|---|---|---|
| Decision | `Middleware\Shield` | rate limits, payload and header scanning, reputation, the verdict | write to storage directly |
| State | `Middleware\SecurityMiddleware` | blocks, incident journal, failed-attempt counters, cleanup, statistics | detect anything |
| Detection | `Detection\*` | scoring a value, one rule per concern | know about storage |
| Knowledge | `ThreatIntel\*` | a provider answer, the cache, the breaker | block a request |

```mermaid
flowchart LR
    APP["Application code"] --> SH["Shield: the decision"]
    SH --> DET["Detection rules: 6 rules and the registry"]
    SH --> TI["ReputationChecker: providers, cache, quota, breaker"]
    SH --> RL["RateLimiter: database or Redis"]
    SH --> SM["SecurityMiddleware: the state"]
    SM --> BS["MysqlBlockStore"]
    SM --> STATS["incidents, counters, cleanup, statistics"]
    BS --> DB["php_shield_* tables"]
    RL --> DB
    TI --> DB
```

## The decisions behind the shape

| ADR | Decision | Consequence |
|---|---|---|
| [001](https://github.com/paulmann/PHP-Shield/blob/main/docs/adr.md) | each detection category is a class implementing `RuleInterface`, built by `RuleFactory` | rules are testable in isolation, projects register their own without forking |
| 002 | scores accumulate, only a total above `block_threshold` blocks | no regex can ban a customer forever; permanent blocks are an operator action |
| 003 | forwarded headers are read right to left, only from `trusted_proxies` | no client-chosen address, no silent bypass |
| 004 | `BlockStoreInterface` and `RateLimiterInterface` are the only storage contracts | MySQL is one implementation; tests need no services |
| 005 | detection and state are separate classes | one source of truth each; the state API works from a login handler or a CLI |
| 006 | infrastructure failures fail open and log | a database or API outage is not a site outage |
| 007 | one client for both AbuseIPDB communities | `.com`, `.ru` or both, in a configured order, verified by contract tests |
| 008 | cache, quota window and circuit breaker sit in front of `/check` | a burst costs one query, a broken provider costs nothing |
| 009 | every expiry is computed in SQL | the library is time-zone agnostic; `date()` is forbidden in stored comparisons |

The full text, with alternatives and rejected options, is in
[docs/adr.md](https://github.com/paulmann/PHP-Shield/blob/main/docs/adr.md).

## Request flow

```mermaid
flowchart TD
    REQ(["HTTP request"]) --> INSPECT["Shield::inspect()"]
    INSPECT --> ENABLED{"enabled?"}
    ENABLED -->|no| ALLOW(["allow"])
    ENABLED -->|yes| TRUSTED{"client IP in trusted_ips?"}
    TRUSTED -->|yes, never counted| ALLOW
    TRUSTED -->|no| BLOCKED{"address blocked?"}
    BLOCKED -->|yes| DENY403["403 ip_blocked"]
    BLOCKED -->|no| FAILS{"failed attempts at limit?"}
    FAILS -->|yes| BLOCK1["block once"]
    BLOCK1 --> DENY403B["403 too_many_failures"]
    FAILS -->|no| RATE{"rate limit exceeded?"}
    RATE -->|yes| BLOCK2["block 300 s"]
    BLOCK2 --> DENY429["429 rate_limited"]
    RATE -->|no| REPUTATION["IP reputation: cache, provider fallback, breaker"]
    REPUTATION --> SCORED{"abuse score"}
    SCORED -->|block_score and above| BLOCK3["block + incident"]
    BLOCK3 --> DENY403C["403 ip_reputation"]
    SCORED -->|flag_score and above| JOURNAL1["journal only"]
    JOURNAL1 --> SCAN["payload scan: 6 rules over GET, POST, REQUEST_URI"]
    SCORED -->|below, no data or outage| SCAN
    SCAN --> FINDING{"score"}
    FINDING -->|block mode, threshold reached| BLOCK4["journal + block"]
    BLOCK4 --> DENY403D["403 threat_detected"]
    FINDING -->|challenge mode, threshold reached| DENY403E["403 challenge_required"]
    FINDING -->|suspicious| JOURNAL2["journal once per 10 min"]
    JOURNAL2 --> HEADERS["header scan: User-Agent"]
    FINDING -->|clean| HEADERS
    HEADERS -->|scanner| JOURNAL3["journal or block"]
    HEADERS -->|clean| ALLOW
    JOURNAL3 --> ALLOW
    ALLOW --> DECISION["decision array: blocked, status, reason, detail, score, findings"]
    DENY403 --> DECISION
    DENY403B --> DECISION
    DENY429 --> DECISION
    DENY403C --> DECISION
    DENY403D --> DECISION
    DENY403E --> DECISION
    DECISION --> APP(["application or error response"])
    classDef allow fill:#d3f9d8,stroke:#2f9e44,color:#000000
    classDef deny fill:#ffe3e3,stroke:#c92a2a,color:#000000
    classDef step fill:#e7f5ff,stroke:#1c7ed6,color:#000000
    class ALLOW,APP allow
    class DENY403,DENY403B,DENY429,DENY403C,DENY403D,DENY403E deny
    class INSPECT,SCAN,DECISION step
```

The order is the design: cheap checks first, network last, and a trusted address exits before any work
is done.

## Extension points

| You want | Implement | Wire it with |
|---|---|---|
| a detection rule | `Detection\AbstractRule` | `RuleFactory::register()`, then `enabled_rules` |
| a reputation provider | `ThreatIntel\ReputationProviderInterface` | `ShieldFactory::buildProviders()` |
| a storage backend | `Storage\BlockStoreInterface` (+ optional capability interfaces) | `ShieldFactory::createWithComponents()` |
| a rate limiter | `RateLimiting\RateLimiterInterface` | `ShieldFactory::createWithComponents()` |
| a different client IP policy | `Ip\IpResolver` | `createWithComponents(..., ipResolver: ...)` |

## What is deliberately absent

- plugins, events and a container: this library runs inside someone else's request path and must stay
  predictable;
- a queue or a background worker: cleanup is a scheduled call, not a daemon;
- a second storage engine for its own sake: MySQL and Redis cover the deployment shapes this project
  targets, and the interfaces leave the rest to the application.
