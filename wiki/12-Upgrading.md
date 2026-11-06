# Upgrading from SecurityMiddleware 1.x

2.0 is a deliberate break. The package name changed, the decision engine moved into its own class, and
the state class lost the ability to detect. Everything below is mechanical except the last item.

## What changed

| 1.x | 2.0 |
|---|---|
| package `deynekin/security-middleware` | package `paulmann/php-shield`, namespace `Deynekin\PhpShield\` |
| `SecurityMiddleware::isRequestAllowed()` decided | `Middleware\Shield::inspect()` decides; `isRequestAllowed()` remains as a boolean facade |
| one class detected and stored | `Shield` detects, `SecurityMiddleware` stores (ADR-005) |
| `ShieldFactory::create()` returned the middleware | returns `Shield`; `createWithComponents()` needs no MySQL |
| fixed block duration for a high score | severity-based lifetimes |
| `BlockStoreInterface::block($ip, $reason)` | `block($ip, $reason, $severity)`; `countIncidents()` and `getRecentIncidents()` are required |
| default `mode` was `block`, `trusted_ips` covered private ranges | default `monitor`, loopback only |
| — | AbuseIPDB.com / AbuseIPDB.ru reputation |

## Migrating the entry point

```php
// 1.x
$middleware = new SecurityMiddleware($config, $mysqli);
if (!$middleware->isRequestAllowed($_POST, $_SERVER)) {
    http_response_code(403);
    exit;
}
```

```php
// 2.0
$shield = ShieldFactory::create($config, $mysqli);
$decision = $shield->inspect($_POST + $_GET, $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');

if ($decision['blocked']) {
    http_response_code($decision['status']);
    header('Content-Type: application/json');
    exit(json_encode(['error' => $decision['reason'], 'detail' => $decision['detail']]));
}
```

If you only need the boolean, `$shield->isRequestAllowed($request, $server)` still exists — but you lose
the reason, which is what you need when a user complains.

## Migrating state calls

```php
// 1.x
$middleware->blockIp($ip, 'scanner');
// 2.0
$shield->middleware()->blockIp($ip, 'scanner', SecurityMiddleware::SEVERITY_HIGH);
```

`recordIncident()`, `recordFailedAttempt()`, `activeBlocks()`, `stats()` and `cleanup()` moved to the
state object unchanged. The severity constants live on `Middleware\SecurityMiddleware`
(`SEVERITY_LOW`, `SEVERITY_MEDIUM`, `SEVERITY_HIGH`, `SEVERITY_CRITICAL`).

## Migrating a custom store

Implement the new signature and the two required incident methods:

```php
public function block(string $ip, string $reason, string $severity = 'medium'): void;
public function countIncidents(string $ip, int $seconds): int;
public function getRecentIncidents(int $limit): array;
```

Optional capabilities stay optional: `FailedAttemptStoreInterface` and `MaintenanceStoreInterface`.
A store that implements only `BlockStoreInterface` keeps working — counters and cleanup are simply not
available.

## Schema migration

`auto_migrate` adds the `severity` column and the two new tables. In production, apply
`../migrations/schema.sql` and keep `auto_migrate = false`. The drift between the runtime DDL and the
schema file (F-15) is fixed, so both paths produce the same table set.

## The one thing to change deliberately

The default mode is now `monitor`, and `trusted_ips` no longer exempts private ranges. A deployment
that relied on the old defaults will appear to "stop blocking":

1. run in `monitor` for a few days and read the journal;
2. set `trusted_ips` to the networks you actually trust — nothing wider;
3. switch to `block`.

That is the intended sequence: the 1.x defaults either blocked real users or exempted whole networks,
and both are defects rather than features.
