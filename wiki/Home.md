# PHP Shield

![PHP Shield](https://raw.githubusercontent.com/paulmann/PHP-Shield/main/assets/social-preview.png)

**A modular request firewall for PHP**: local threat detection, IPv4/IPv6 reputation (AbuseIPDB.com
and AbuseIPDB.ru), rate limiting, IP blocking with severity-based lifetimes, an incident journal and
an admin dashboard.

One entry point, `Deynekin\PhpShield\Middleware\Shield::inspect()`, answers a single question: **may
this request proceed, and if not, why?**

## What it is

| Layer | Class | Responsibility |
|---|---|---|
| Decision | `Middleware\Shield` | rate limits, payload and header scanning, IP reputation, the verdict |
| State | `Middleware\SecurityMiddleware` | blocks, incident journal, failed-attempt counters, cleanup, statistics |
| Detection | `Detection\*` | pluggable rules that score a payload |
| Knowledge | `ThreatIntel\*` | AbuseIPDB.com / AbuseIPDB.ru reputation with cache and circuit breaker |

Two policy rules shape every decision:

- **A single finding never bans anyone.** Scores accumulate and only a total above `block_threshold`
  blocks. A permanent block is an operator decision, never a regex.
- **Nothing fails closed on infrastructure trouble.** A database, Redis or API outage means "no
  data", not "deny".

## How a request is decided

`inspect()` walks the layers in a fixed order: cheap checks first, the network last, and a trusted
address leaves before any work is done. Every branch ends in the same decision array, so the caller
reads one shape whether the request was allowed or refused.

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

The mode branches sit next to the score, not at the top: `monitor` and `challenge` change the reaction
to a finding, not the order of the checks. The order itself is listed in
[Getting started](01-Getting-Started.md).

## What it is not

It is not a replacement for prepared statements, output escaping, CSP, authentication or session
security. It buys time and visibility; it does not fix application defects.

## Install

```bash
composer require paulmann/php-shield
```

```php
$config = require 'vendor/paulmann/php-shield/config/default.php';
$config['mode'] = 'monitor';                 // start safe
$shield = ShieldFactory::create($config, new mysqli($host, $user, $pass, $db));

$decision = $shield->inspect($_GET + $_POST, $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');
```

## Where to go next

| If you want to… | Read |
|---|---|
| Install it and get a first decision | [Getting started](01-Getting-Started.md) |
| Know what every configuration key does | [Configuration reference](02-Configuration.md) |
| Understand or tune detection | [Detection rules](03-Detection-Rules.md) |
| Turn on AbuseIPDB reputation | [IP reputation](04-IP-Reputation.md) |
| Understand modes and block lifetimes | [Modes and block lifetimes](05-Modes-and-Blocks.md) |
| Work with blocks, incidents and counters | [State and storage](06-State-and-Storage.md) |
| Choose a rate limiter | [Rate limiting](07-Rate-Limiting.md) |
| Secure the admin dashboard | [Admin dashboard](08-Admin-Dashboard.md) |
| Run behind nginx, Cloudflare or a balancer | [Reverse proxies and client IP](09-Reverse-Proxies.md) |
| Deploy to production | [Production checklist](10-Production-Checklist.md) |
| Fix something that behaves oddly | [Troubleshooting](11-Troubleshooting.md) |
| Migrate from SecurityMiddleware 1.x | [Upgrading](12-Upgrading.md) |
| Understand the design | [Architecture](13-Architecture.md) |
| Know what the security review found | [Security](14-Security.md) |
| Run the tests and the analysis | [Development](15-Development.md) |

## Requirements

- PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`
- Optional: `ext-mysqli` (MySQL storage and dashboard), `ext-redis` (Redis rate limiter),
  `ext-curl` (reputation lookups)

## Elsewhere

- [Repository](https://github.com/paulmann/PHP-Shield) — README in six languages:
  [English](https://github.com/paulmann/PHP-Shield/blob/main/README.md),
  [Русский](https://github.com/paulmann/PHP-Shield/blob/main/README.ru.md),
  [Deutsch](https://github.com/paulmann/PHP-Shield/blob/main/README.de.md),
  [Español](https://github.com/paulmann/PHP-Shield/blob/main/README.es.md),
  [中文](https://github.com/paulmann/PHP-Shield/blob/main/README.zh.md),
  [हिन्दी](https://github.com/paulmann/PHP-Shield/blob/main/README.hi.md)
- [Architecture decision records](https://github.com/paulmann/PHP-Shield/blob/main/docs/adr.md)
- [Security review](https://github.com/paulmann/PHP-Shield/blob/main/docs/security-review.md)
- [Reporting a vulnerability](https://github.com/paulmann/PHP-Shield/blob/main/SECURITY.md)

## License

MIT.
