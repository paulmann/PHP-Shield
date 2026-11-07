# IP reputation: AbuseIPDB.com and AbuseIPDB.ru

Both services speak the same API v2 contract — `/check`, the `Key:` header, the same envelopes — so
the library ships one client, `ThreatIntel\AbuseIpDbProvider`, parameterised by base URL, and
`ReputationChecker` tries the configured providers in order.

## Asynchronous by default

The reputation layer never sits in the request path. `Shield::inspect()` reads the cache and, on a
miss, writes one row into `php_shield_reputation_queue`; the answer is fetched by a worker that runs
from cron. Switch to `'mode' => 'sync'` only for low-traffic endpoints, tests and CLI tools.

| Mode | Request path | When the verdict applies |
|---|---|---|
| `async` (default) | cache read + at most one `INSERT` | from the next request after the worker stored the answer |
| `sync` | one HTTP call bounded by `timeout` | immediately |

```bash
# every minute
* * * * * php /path/to/PHP-Shield/tools/reputation-worker.php >> /var/log/php-shield-reputation.log 2>&1

php tools/reputation-worker.php --status       # queue size, providers, mode
php tools/reputation-worker.php --ip=8.8.8.8   # one address now (debugging)
```

The worker prints one line, suitable for a log:

```
processed=2 fetched=2 empty=0 failed=0 skipped=0 queued=0
```

Consequences worth knowing:

- the first visit of a new address is never delayed and never blocked *because of* AbuseIPDB — the
  score is confirmed or cleared on a following request;
- `per_run` caps the calls per worker run, so the daily quota is spent gradually;
- a failed lookup stays in the queue with `retry_after` backoff instead of being dropped;
- if the worker does not run, nothing breaks: the shield keeps working with the local rules and the
  queue simply grows.

## Configuration

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'mode' => 'async', // async (default) | sync
    'block_score' => 75,
    'flag_score' => 25,
    'cache_ttl' => 86400,
    'max_age_days' => 90,
    'timeout' => 2,        // sync mode only
    'queue_batch' => 50,   // addresses claimed per worker run
    'per_run' => 100,      // lookups per worker run (quota guard)
    'retry_after' => 300,  // retry delay after a failed lookup
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
- **The request path never calls the API** in `async` mode: it queues the address and moves on.
- **Backoff on failure.** A lookup that could not be answered stays queued with `retry_after`
  seconds, so an outage cannot spin the worker or burn the quota.
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
