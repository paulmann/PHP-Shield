# Troubleshooting

Start with the decision array. It names the layer that refused the request, so most rows below are read
off `reason` and `findings`.

| Symptom | Cause | Fix |
|---|---|---|
| Everything is allowed | `mode = monitor` | switch to `block` after tuning |
| `ConfigurationException: Unknown mode` | typo such as `blocks` | use `monitor`, `challenge` or `block` |
| `ConfigurationException` about a rule name | `enabled_rules` lists a rule that is not registered | remove the name or register the rule first |
| Blocks disappear immediately | PHP and MySQL clocks differ | already handled: expiries use the database clock; check `auto_migrate` and that the schema matches |
| `403` for a legitimate client behind a proxy | `trusted_proxies` is empty, so the proxy address is used as the client | add the proxy network, see [Reverse proxies](09-Reverse-Proxies.md) |
| A client bypasses everything | a forged `X-Forwarded-For` matches a `trusted_ips` entry | keep `trusted_ips` narrow; verify with `curl -H 'X-Forwarded-For: 127.0.0.1'` |
| Reputation never blocks | disabled, no key, score below `block_score`, or `monitor` mode | read [IP reputation](04-IP-Reputation.md) — the checklist there is ordered |
| Reputation stops working after an outage | circuit breaker is open | wait `circuit_breaker.cooldown` seconds |
| Rate limit never triggers | `rate_limiter = database` and the table is missing | apply `../migrations/schema.sql` or enable `auto_migrate` |
| Legitimate bursts get `429` | shared/NAT address, or the per-minute limit is below the page's own subrequests | raise `minute.limit`, or exclude static routes |
| Old tables lack `severity` | upgrade from 1.x | `auto_migrate` adds the column, or run the `ALTER` from `schema.sql` |
| Fatal error `fetch_assoc() on bool` | fixed in 2.0.0 (F-05) | upgrade |
| `JsonException` while handling a threat | fixed in 2.0.0 (F-04): invalid UTF-8 is substituted | upgrade |
| Dashboard login does nothing | `admin.password_hash` is empty — that disables login by design | generate a hash and set it |
| Dashboard shows the wrong configuration | a different configuration file is deployed | `inspect()` and the dashboard must use the same array |

## "It blocked a legitimate request"

1. Find the incident: rule, score, field, endpoint, address.
2. Reproduce in `monitor` mode with the same payload.
3. Decide: lower the rule score, disable the rule for that endpoint, or whitelist the address.
4. Do not raise `block_threshold` to fix one endpoint — it hides real attacks everywhere.
5. Check the unblock path: the address stays blocked for its severity lifetime, so unblock it
   explicitly with `unblockIp()` or the dashboard.

## "Nothing is blocked in `block` mode"

| Check | How |
|---|---|
| Is the shield actually called? | log `$decision['reason']` for a request that should trip a rule |
| Is the address trusted? | it would return `allowed` before any scan; look at `trusted_ips` and the resolved client IP |
| Is the score above the threshold? | one rule hit is often 30–50; a single finding should not block by design |
| Is the rule enabled? | `enabled_rules` and `rules.<name>.enabled` |
| Is the payload scanned at all? | `enable_content_scanning`, `scan_request_uri`, and the field names you pass in |

## "It is slow"

Reputation is the only layer that talks to the network: 2 s timeout by default, a shared cache, a
circuit breaker and a quota window in front of it. If the request path is slow, check in this order:

1. `cache_ttl` — a short TTL means a query per request;
2. provider latency and timeouts in the journal;
3. the database limiter under concurrency — move to Redis;
4. `auto_migrate` accidentally `true` in production (DDL on every request, F-06).

## Diagnosing without a dashboard

```php
$shield = ShieldFactory::create($config, $mysqli);
$decision = $shield->inspect($_GET + $_POST, $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');
error_log(json_encode($decision));

$stats = $shield->middleware()->stats();
$recent = $shield->middleware()->recentIncidents(20);
```

## Still stuck

Open an issue with the decision array, the minimum configuration and the PHP/extension versions — see
[SUPPORT.md](https://github.com/paulmann/PHP-Shield/blob/main/SUPPORT.md). For a vulnerability, use the
private route in
[SECURITY.md](https://github.com/paulmann/PHP-Shield/blob/main/SECURITY.md), never a public issue.
