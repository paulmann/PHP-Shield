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
];
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
