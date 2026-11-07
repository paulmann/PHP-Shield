# Production checklist

A deploy checklist, in the order that avoids surprises. Each item is something that has gone wrong in
a real deployment of this pattern.

## 1. Observe before you enforce

- [ ] `mode = monitor`
- [ ] `auto_migrate = true` for the first run (or apply `../migrations/schema.sql` yourself)
- [ ] the dashboard shows live statistics
- [ ] `php_shield_incidents` is filling with type, severity, endpoint and field

## 2. Tune against your own traffic

- [ ] read a week of incidents; disable rules that only fire on your own content editors
- [ ] set `trusted_ips` to your own networks and monitoring, nothing wider
- [ ] set `trusted_proxies` to exactly the proxies in front of PHP
- [ ] verify the client address with a forged `X-Forwarded-For` (see
      [Reverse proxies](09-Reverse-Proxies.md))

## 3. Harden the storage

- [ ] `auto_migrate = false` — no DDL on the request path
- [ ] `migrations/schema.sql` applied, schema drift checked (`tools/db-selftest.php`)
- [ ] the database user of the shield has no `DROP`, `GRANT` or `FILE` privilege
- [ ] `DatabaseRateLimiter::prune()` and `cleanup()` are scheduled
- [ ] `tools/reputation-worker.php` runs from cron every minute when `ip_reputation.enabled` is true
  (async mode); `--status` shows the queue size
- [ ] The reputation queue is drained: `SELECT COUNT(*) FROM php_shield_reputation_queue` stays small

## 4. Concurrency

- [ ] `rate_limiter = redis` if more than one PHP worker can accept requests
- [ ] Redis is not reachable from the internet
- [ ] a Redis outage was tested: requests must still pass (fail open) and be logged

## 5. Reputation

- [ ] `ip_reputation.enabled = true` with `block_score` high (for example 90) for the first days
- [ ] keys live in the environment (`ABUSEIPDB_API_KEY`, `ABUSEIPDB_RU_API_KEY`), never in the tree
- [ ] `tools/live-abuseipdb.php` answers once, and the quota window is understood
- [ ] the second provider is configured as a fallback

## 6. Dashboard

- [ ] `admin.password_hash` set from the environment; an empty hash disables login
- [ ] HTTPS only, `cookie_secure` resolved from `$_SERVER['HTTPS']`
- [ ] path restricted at the web-server level (allowlist, VPN or HTTP auth)
- [ ] no secret in the dashboard's configuration file (`/public/admin/config.php` is git-ignored)

## 7. Headers and response

- [ ] `SecurityHeaders::send()` called early in the request
- [ ] the 403/429 response body is JSON or HTML as your clients expect — `inspect()` gives you the
      status, the reason and a detail string

## 8. Enforce, then watch

- [ ] switch to `mode = block`
- [ ] watch the 403/429 rate for a day; an unexpected spike is a false positive, not a win
- [ ] add the monitor to your alerting: incident rate, block count, reputation provider errors
- [ ] document the rollback: one configuration key back to `monitor`

## Rollback

```php
$config['mode'] = 'monitor';   // stop blocking immediately, keep observing
```

Nothing else changes: blocks already issued stay until they expire, and `unblockIp()` clears them if
you need that too. There is no migration to undo.
