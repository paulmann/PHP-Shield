# Reverse proxies and client IP

Every decision — blocks, counters, rate limits, reputation — is keyed by the client address. Getting
that address wrong does not merely produce bad statistics: it produces a bypass.

## The rule

`X-Forwarded-For` is honoured **only** when `REMOTE_ADDR` is listed in `trusted_proxies`, and the chain
is read **from right to left**, skipping trusted hops:

```text
X-Forwarded-For: 1.2.3.4, 203.0.113.9      (1.2.3.4 was supplied by the client, 203.0.113.9 appended by nginx)
REMOTE_ADDR:     10.0.0.5                  (trusted proxy)
→ client = 203.0.113.9
```

Reading the left-most entry — the intuitive reading — hands the client control of its own identity. If
that forged address happens to match a `trusted_ips` entry, the whole shield is bypassed. This was a
real defect in 1.x, fixed in 2.0.0 and pinned by `IpResolverTest`.

`X-Real-IP` is handled the same way: only from a trusted proxy.

## Configuration

```php
$config['trusted_proxies'] = [
    '10.0.0.5',          // nginx on the same host
    '172.16.0.0/12',     // the load balancer network
];
```

Keep the list exact. A `/8` that covers more than your proxies is the same bug in a different shape.

## Recipes

**nginx on the same host:**

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

```php
$config['trusted_proxies'] = ['127.0.0.1', '::1'];
```

**Cloudflare:** the client address is in `CF-Connecting-IP`, which the library does not read (it is
another header a client could try to set). Either restrict origin access to Cloudflare ranges and let
`X-Forwarded-For` carry the address, or read `CF-Connecting-IP` yourself and pass your own
`$server['REMOTE_ADDR']` into `inspect()`.

**Two proxies in a row** (CDN → nginx → PHP): the chain is `client, cdn-edge`; reading right to left
and skipping trusted hops lands on the CDN edge address unless the edge is also in `trusted_proxies`.
List both hops.

## IPv6

`IpResolver` normalises IPv6, including zone identifiers (`fe80::1%eth0`) and compressed forms, so
`2001:db8::1` and `2001:0db8:0000::1` are the same address. CIDR matching in `Ip\CidrMatcher` uses a
single binary comparison for both families.

## Verifying your setup

Log what the shield decided, not what you assume:

```php
error_log(json_encode([
    'remote' => $_SERVER['REMOTE_ADDR'] ?? null,
    'forwarded' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
    'client' => $decision['detail'],
]));
```

Then send a request with a forged left-most entry:

```bash
curl -H 'X-Forwarded-For: 127.0.0.1' https://example.test/
```

If the answer shows `127.0.0.1` as the client, stop and fix `trusted_proxies` before enabling `block`
mode: every other protection is downstream of this one.
