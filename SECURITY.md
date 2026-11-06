# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | yes |
| 1.x | no (upgrade guide: `docs/wiki.md` → *Upgrading from SecurityMiddleware 1.x*) |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

- **Private report:** <https://github.com/paulmann/PHP-Shield/security/advisories/new>. If GitHub is unavailable to you, open a minimal issue asking for a private channel — without the details.
- Include: affected version, a reproduction (request payload or config), the observed and the
  expected behaviour, and whether the issue is remotely exploitable.
- You will get an initial answer within three working days.

Please give us a reasonable window to ship a fix before publishing details. Credit is given in
`CHANGELOG.md` unless you prefer to stay anonymous.

## Scope

In scope:

- bypass of detection, rate limiting or IP blocking;
- client IP spoofing through forwarded headers;
- authenticated or unauthenticated access to the admin dashboard, CSRF, session handling;
- injection in the storage layer or in the admin output;
- credential or payload leakage into logs, the dashboard or error output;
- denial of service caused by the library itself on a normal request path.

Out of scope:

- findings that require the attacker to edit configuration files or the database;
- detection misses for obfuscated payloads that remain syntactically valid — signature detection is
  a layer, not a guarantee (see `docs/security-review.md`, *Residual risks*);
- behaviour of third-party services (AbuseIPDB.com, AbuseIPDB.ru) outside the library's own contract;
- reports produced by an automated scanner without a reproduction.

## What the library promises

- Trusted addresses are never blocked and never counted.
- A single detection never produces a permanent ban.
- Infrastructure failures (database, Redis, reputation API) never block a visitor; they are logged.
- Secrets are never written to logs or rendered by the dashboard.
