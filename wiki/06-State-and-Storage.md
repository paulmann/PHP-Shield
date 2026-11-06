# State and storage

`Middleware\SecurityMiddleware` owns state and nothing else: blocks, the incident journal,
failed-attempt counters, cleanup and statistics. It never scans a payload — that is the decision
layer's job (ADR-005).

Reach it through the shield:

```php
$state = $shield->middleware();
```

## Blocks

```php
$state->isIpBlocked('203.0.113.5');

$state->blockIp('203.0.113.5', 'scanner', $state::SEVERITY_HIGH);   // temporary, lifetime from severity
$state->blockPermanently('203.0.113.5', 'manual decision');          // operator only
$state->unblockIp('203.0.113.5');

$state->activeBlocks(50);      // the 50 newest active blocks, for a dashboard or a CLI report
```

## Failed attempts

```php
$state->recordFailedAttempt('203.0.113.5');   // call it from your login handler
$state->failedAttempts('203.0.113.5');
$state->clearFailedAttempts('203.0.113.5');   // after a successful login
```

At `max_failed_attempts` (25) the next request is blocked once and the counter is cleared.

## Incidents

```php
$state->recordIncident('203.0.113.5', 'login_bruteforce', 'Ten failed logins', 'high', ['endpoint' => '/login'], $userId);
$state->recentIncidentCount('203.0.113.5', 600);   // last 10 minutes
$state->recentIncidents(50);
```

The `context` argument is JSON-encoded with invalid UTF-8 substituted, so a binary payload cannot
turn threat handling into a fatal `JsonException` (that was a 1.x defect).

## Statistics and maintenance

```php
$stats = $state->stats();   // totals by type and severity, top addresses, active block count
$state->cleanup(30);        // retention in days: expired blocks, old incidents, stale counters
```

Schedule both kinds of cleanup: `cleanup()` for the shield tables and
`DatabaseRateLimiter::prune()` for the rate-limit table.

```sql
DELETE FROM php_shield_ip_blocks        WHERE block_type = 'temporary' AND expires_at <= NOW();
DELETE FROM php_shield_incidents        WHERE occurred_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
DELETE FROM php_shield_failed_attempts  WHERE last_attempt_at < DATE_SUB(NOW(), INTERVAL 1 DAY);
DELETE FROM php_shield_rate_limit       WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 DAY);
DELETE FROM php_shield_ip_reputation    WHERE expires_at <= NOW();
```

## Tables

| Table | Content |
|---|---|
| `php_shield_ip_blocks` | temporary and permanent blocks, with `severity`, `reason` and `expires_at` |
| `php_shield_incidents` | the journal: type, severity, description, JSON context, address, user id |
| `php_shield_failed_attempts` | counters per address with the last attempt time |
| `php_shield_rate_limit` | the database limiter's counters |
| `php_shield_ip_reputation` | cached reputation answers with their expiry |

The schema is `../migrations/schema.sql`. Tables are created on first use while `auto_migrate` is
`true`; in production apply the schema once and set `auto_migrate` to `false`, so no DDL runs on the
request path.

## Storage interfaces

| Interface | Purpose |
|---|---|
| `Storage\BlockStoreInterface` | blocks, incidents, statistics — the minimum a state store must do |
| `Storage\FailedAttemptStoreInterface` | optional: counters and escalation |
| `Storage\MaintenanceStoreInterface` | optional: retention cleanup and pruning |

A minimal custom store implements only the first one and the shield degrades gracefully: counters and
cleanup simply stop being available. `MysqlBlockStore` implements all three.

```php
$shield = ShieldFactory::createWithComponents($blockStore, $rateLimiter, $config);
```

A custom store must keep the clock contract: compare and compute expiries in SQL
(`NOW()`, `DATE_ADD`, `DATE_SUB`), never with `date()` in PHP.
