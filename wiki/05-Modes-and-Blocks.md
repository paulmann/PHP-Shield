# Modes and block lifetimes

## The three modes

| Mode | Hard finding | Suspicious finding | Rate limit |
|---|---|---|---|
| `monitor` | journaled | journaled once per 10 minutes | journaled |
| `challenge` | `403 challenge_required`, no block | journaled | block + `429` |
| `block` | block for a severity lifetime + `403` | journaled | block + `429` |

`monitor` is the default on purpose: signature detection needs tuning per application, and a firewall
that starts in `block` mode teaches operators to disable it.

`challenge` refuses the request without remembering the address — useful when the same NAT address
serves many legitimate users and you do not want a block at all.

## Block lifetime

Lifetime = `block_duration` × `severity_block_multipliers[severity]`:

| Severity | Multiplier | Default lifetime (`block_duration` = 3600) |
|---|---|---|
| `low` | 0.5 | 30 minutes |
| `medium` | 1.0 | 1 hour |
| `high` | 4.0 | 4 hours |
| `critical` | 12.0 | 12 hours |

Severity comes from the finding: a `critical` rule score plus reputation produces `critical`, a single
suspicious header produces `low`. Rate-limit blocks use their own short window,
`rate_limit_block_duration` (300 s), so a burst from a shared or NAT address cannot lock out an office
for an hour.

Expiries are computed by the database (`NOW()`, `DATE_ADD`), never by PHP. A PHP/MySQL time-zone
difference therefore cannot make a fresh block expire instantly — that defect existed in 1.x (ADR-009).

## Permanent blocks

A permanent block is never automatic. It is an operator action:

```php
$state = $shield->middleware();
$state->blockPermanently('203.0.113.5', 'manual decision after review');
```

or the "block permanently" form in the dashboard. Everything else expires on its own.

## Escalation by failed attempts

When `recordFailedAttempt()` brings a counter to `max_failed_attempts` (25), the next request from
that address is blocked once and the counter is cleared:

```php
// in your login handler, after a wrong password
$shield->middleware()->recordFailedAttempt($clientIp);
```

This is the one path that blocks without a detection finding; it exists because credential stuffing
produces perfectly valid HTTP requests.

## Choosing a mode for a rollout

| Phase | Mode | What you look at |
|---|---|---|
| 1. Observe | `monitor` | `php_shield_incidents`: which rules fire, on which endpoints |
| 2. Tune | `monitor` | lower noisy rule scores, disable rules per endpoint, widen `trusted_ips` |
| 3. Enforce | `block` | the 403/429 rate, and whether support tickets appear |
| 4. Reputation | `block` | `ip_reputation` on, first with `block_score` high, then lowered |

Expect to revisit the thresholds: a new feature that accepts rich user input will start producing
findings, and the journal will say so before a user complains.
