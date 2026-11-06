# IP reputation: AbuseIPDB.com and AbuseIPDB.ru

Both services speak the same API v2 contract — `/check`, the `Key:` header, the same envelopes — so
the library ships one client, `ThreatIntel\AbuseIpDbProvider`, parameterised by base URL, and
`ReputationChecker` tries the configured providers in order.

## Configuration

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'block_score' => 75,
    'flag_score' => 25,
    'cache_ttl' => 86400,
    'max_age_days' => 90,
    'timeout' => 2,
    'circuit_breaker' => ['failures' => 5, 'cooldown' => 120],
    'providers' => [
        ['name' => 'abuseipdb.com', 'base_url' => 'https://api.abuseipdb.com/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_API_KEY'],
        ['name' => 'abuseipdb.ru',  'base_url' => 'https://abuseipdb.ru/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_RU_API_KEY'],
    ],
];
```

`api_key` stays `null`; the key is read from the environment variable named by `api_key_env`. Never
commit a key, and never put one into the dashboard configuration file.

## How a score becomes a decision

| `abuseConfidenceScore` | Result |
|---|---|
| `>= block_score` and not whitelisted | incident + block (severity `high`, `critical` from 90) + `403 ip_reputation` |
| `>= flag_score` | one `ip_reputation_flag` incident per 10 minutes, request allowed |
| below `flag_score` | ignored |
| `isWhitelisted = true` | always ignored |

In `monitor` mode a high score is journaled and the request still passes.

## Operational guarantees

- **Cache first.** A hit costs no network and is shared through `php_shield_ip_reputation`.
- **Private addresses are never queried.** Loopback, RFC 1918, CGNAT and link-local ranges are
  skipped: a local address has no public reputation.
- **Provider fallback.** A failing provider passes the question to the next one; the answer records
  which provider produced it in `findings` as `ip_reputation:<provider>`.
- **Quota discipline.** A `429` opens a window taken from `Retry-After` or `X-RateLimit-Reset`, and
  nothing is retried in-process: every following lookup waits instead of burning the remaining quota.
- **Circuit breaker.** After `circuit_breaker.failures` consecutive errors a provider is skipped for
  `cooldown` seconds, then tried again.
- **Fail open.** A timeout, a 5xx or a rejected key never blocks a visitor — the shield continues with
  local rules and journals the outage.

## Testing the integration

```bash
export ABUSEIPDB_API_KEY=your-key
php tools/live-abuseipdb.php 8.8.8.8

export ABUSEIPDB_RU_API_KEY=your-key
php tools/live-abuseipdb.php 8.8.8.8 --provider=ru
```

`tools/live-abuseipdb.php` prints the raw answer, the parsed `IpReputation` and whether the configured
thresholds would block. It makes exactly one request: quota is not free.

## When reputation "does not block"

Work through this list in order — each item has been seen in the field:

1. `ip_reputation.enabled` is `false`;
2. `mode` is `monitor` (reputation is journaled, never blocked);
3. the key is missing, empty or rejected — the journal shows a provider error;
4. the score is below `block_score` — `flag_score` only journals;
5. the address is whitelisted by the provider (`isWhitelisted = true`);
6. the circuit breaker is open after an outage — wait for `cooldown`;
7. the address is private or reserved, so it was never queried.

## Cost control

| Knob | Effect |
|---|---|
| `cache_ttl` | 86 400 s means one query per address per day |
| `block_score` / `flag_score` | a higher `flag_score` means fewer journal entries, the same number of queries |
| `max_age_days` | larger windows return more history, not more requests |
| `timeout` | 2 s is enough; a longer timeout only slows the request path when the provider is down |

AbuseIPDB quotas are per account; a per-address cache is the only real protection, and it is on by
default.
