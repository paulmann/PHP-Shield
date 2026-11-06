# Rate limiting

A rate limit answers a different question than detection: not "is this payload hostile?" but "is this
address behaving like a machine?". Both limiters implement `RateLimiting\RateLimiterInterface`, so an
existing limiter can be plugged in.

## Defaults

```php
'rate_limits' => [
    'minute' => ['limit' => 60,    'window' => 60],
    'hour'   => ['limit' => 1000,  'window' => 3600],
    'day'    => ['limit' => 10000, 'window' => 86400],
],
```

Each window is checked per address **and** per endpoint, so a project that passes a specific endpoint
name to `inspect()` gets separate budgets for `/login` and `/api/search`.

## The two backends

| Backend | Mechanism | Strength | Weakness |
|---|---|---|---|
| `DatabaseRateLimiter` | two statements: count, then insert | no extra service, survives restarts | a burst can overshoot by the number of in-flight requests between the two statements |
| `RedisRateLimiter` | atomic `INCR` + `EXPIRE` | exact under concurrency, fast | one more service; fails open if Redis is unreachable |

Choose the database limiter for low and medium traffic and a single web node. Move to Redis as soon as
two PHP workers can accept requests at the same moment and precision matters — which is most
production sites.

```php
$config['rate_limiter'] = 'redis';
$config['redis'] = ['host' => '127.0.0.1', 'port' => 6379, 'prefix' => 'phpshield:rl:'];
```

## What a broken limit does

- `block` mode: the address is blocked for `rate_limit_block_duration` (300 s) and the request gets
  `429 rate_limited`;
- `challenge` mode: the same block and `429`;
- `monitor` mode: the event is journaled, the request proceeds.

The short window is intentional. A shared address behind carrier-grade NAT can produce a legitimate
burst; locking an office out for an hour because one phone retried is a worse failure than letting the
burst through.

## Maintenance

The database limiter leaves rows behind. Prune them on a schedule:

```php
$limiter->prune();
```

or in SQL:

```sql
DELETE FROM php_shield_rate_limit WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 DAY);
```

The Redis limiter needs no maintenance: entries expire on their own.

## Tuning notes

| Symptom | Likely cause | What to change |
|---|---|---|
| Legitimate pages get `429` | the per-minute limit is below the page's own asset/subrequest count | raise `minute.limit` or exclude static routes from `inspect()` |
| A single client floods and the counter barely moves | the address is a proxy for many users | put the proxy in `trusted_proxies`, so the client address is used |
| The limit never triggers | `rate_limiter` is `database` and the table is missing (`auto_migrate` off, schema not applied) | apply `../migrations/schema.sql` |
| Counters reset on deploy | the Redis prefix changed, or Redis was flushed | keep `redis.prefix` stable |
