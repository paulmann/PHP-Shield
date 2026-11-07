# Admin dashboard

`public/admin/index.php` is a single-file dashboard over the same state API the application uses.

It shows:

- statistics: incidents by type and severity, top addresses, active block count;
- the active blocks, with the ability to block and unblock manually;
- the effective configuration with passwords, tokens and keys masked.

## Security model

| Control | Behaviour |
|---|---|
| Authentication | `admin.username` plus `admin.password_hash`; an empty hash disables login entirely |
| Login throttling | 5 failures → 5-minute lockout for that address |
| Session | id regenerated on login, idle timeout `admin.session_timeout` (1 h) |
| Cookie | `HttpOnly`, `SameSite=Strict` by default, `Secure` on HTTPS |
| CSRF | every state-changing form carries a per-session token |
| Output | the configuration dump masks credentials before rendering; incident context is HTML-escaped |

The masked dump is not a licence to put a secret in the configuration file: read keys from the
environment and keep the admin file outside version control (`.gitignore` already excludes
`/public/admin/config.php`).

## Enabling it

```bash
php -r "echo password_hash(getenv('PHP_SHIELD_ADMIN_PASSWORD'), PASSWORD_DEFAULT), PHP_EOL;"
```

```php
$config['admin'] = [
    'enabled' => true,
    'username' => 'admin',
    'password_hash' => getenv('PHP_SHIELD_ADMIN_HASH'),
    'session_timeout' => 3600,
    'cookie_samesite' => 'Strict',
    'cookie_secure' => null,          // null = decide from $_SERVER['HTTPS']
    'allowed_ips' => [],              // empty = no IP restriction (default)
];
```

## IP allowlist

The gate is **off by default**: an empty `admin.allowed_ips` lets everyone reach the login form, which
still needs the password hash. Fill the list and the panel answers `403` to any other address — before
the dashboard opens a database connection.

```php
'allowed_ips' => [
    '203.0.113.0/24',   // office network
    '198.51.100.7',     // jump host (/32)
    '2001:db8::/32',    // IPv6
],
```

- IPv4 and IPv6 CIDR are both accepted; a bare address means `/32`;
- a single string (`'203.0.113.0/24, 198.51.100.7'`) works too, which suits environment-driven config;
- behind a proxy, add the proxy to `trusted_proxies` — the gate resolves the client address through the
  same rules as the shield, and an untrusted `X-Forwarded-For` is ignored on purpose;
- an unreachable panel is worse than a restricted one: keep the break-glass path (web-server auth or a
  VPN) in mind before you enable the list, and verify from a network that *is* on it.

Quick check without a browser:

```php
$access = new Deynekin\PhpShield\Admin\AdminAccess($config);
$access->allows('203.0.113.9');   // true
```

Serve it over HTTPS only, and restrict the path at the web-server level as well: an IP allowlist, a
VPN, or HTTP authentication in front of it. The form is only as strong as the password, and the
password is the only thing between an attacker and a "block permanently" button.

## Operating it

- **Unblock after a false positive.** Find the address in active blocks, unblock it, then tune the rule
  that fired (see [Detection rules](03-Detection-Rules.md)).
- **Permanent blocks are for reviews, not for reflexes.** Check the journal first: a repeated address
  with many low-severity findings is a scanner; a single finding from a customer network is usually a
  false positive.
- **The configuration view is a diagnostic.** If the dashboard shows `mode = monitor` while you
  expected blocking, the deployed configuration is not the one you think.

## Not included on purpose

- multi-user accounts, roles and an audit log — the dashboard is a single-operator tool;
- editing configuration from the browser — a web form that rewrites the security configuration is a
  privilege-escalation surface;
- issuing API tokens — integrate the state API in your own admin instead.
