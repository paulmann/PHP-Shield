# Getting started

## Requirements

| Requirement | Why |
|---|---|
| PHP 8.1 – 8.5 | the package targets the supported matrix, CI runs every version |
| `ext-json` | payload scanning, incident context, dashboard responses |
| `ext-mbstring` | multibyte-safe payload inspection |
| `ext-mysqli` (optional) | MySQL block store, database rate limiter, dashboard |
| `ext-redis` (optional) | Redis rate limiter for concurrent traffic |
| `ext-curl` (optional) | AbuseIPDB.com / AbuseIPDB.ru reputation lookups |

## Install

```bash
composer require paulmann/php-shield
```

No MySQL? Build the shield from components and supply your own `BlockStoreInterface` and
`RateLimiterInterface` — detection, headers and statistics keep working without a database:

```php
$shield = ShieldFactory::createWithComponents($blockStore, $myRateLimiter, $config);
```

## A first request

```php
<?php
require 'vendor/autoload.php';

use Deynekin\PhpShield\ShieldFactory;

$config = require 'vendor/paulmann/php-shield/config/default.php';
$config['mode'] = 'monitor';              // journal everything, block nothing

$mysqli = new mysqli('127.0.0.1', 'user', 'pass', 'dbname');
$shield = ShieldFactory::create($config, $mysqli);

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');

if ($decision['blocked']) {
    http_response_code($decision['status']);
    header('Content-Type: application/json');
    exit(json_encode(['error' => $decision['reason'], 'detail' => $decision['detail']]));
}

// Application logic continues...
```

Run like this for a few days. Nothing is blocked, everything suspicious lands in
`php_shield_incidents` with the rule name, the score and the field. That table is the input to your
tuning.

## The decision array

| Key | Type | Meaning |
|---|---|---|
| `blocked` | bool | may the request proceed |
| `status` | int | HTTP status to send (403, 429 or 200) |
| `reason` | string | machine-readable code, see below |
| `detail` | string | human-readable explanation, safe to log |
| `score` | int | accumulated score of the findings |
| `findings` | string[] | rule names, or `ip_reputation:<provider>` |

Reasons: `ip_blocked`, `too_many_failures`, `rate_limited`, `ip_reputation`, `threat_detected`,
`challenge_required`, `suspicious_user_agent`.

`isRequestAllowed()` returns the same decision reduced to a boolean.

## Order of checks

The order is fixed and intentional — a cheap check never runs after an expensive one:

1. master switch `enabled` → allow;
2. trusted address → allow, never blocked, never counted;
3. active block → deny 403 `ip_blocked`;
4. failed-attempt counter over `max_failed_attempts` → block once, deny 403;
5. rate limits → deny 429 `rate_limited` (journaled in `monitor`);
6. IP reputation → block, journal or ignore;
7. payload scan (GET, POST, `REQUEST_URI`) → score, journal, block, allow;
8. header scan (User-Agent) → journal or block;
9. allow.

## Where the state goes

With MySQL the tables are created on first use (`auto_migrate`). In production apply
`../migrations/schema.sql` once and set `auto_migrate` to `false`, so no DDL runs on the request
path. Table list and maintenance SQL: [State and storage](06-State-and-Storage.md).

## Next steps

1. Read [Configuration reference](02-Configuration.md) and set `trusted_ips` and `trusted_proxies`.
2. Tune with [Detection rules](03-Detection-Rules.md).
3. Add reputation: [IP reputation](04-IP-Reputation.md).
4. Switch mode deliberately: [Modes and block lifetimes](05-Modes-and-Blocks.md).
5. Before production: [Production checklist](10-Production-Checklist.md).
