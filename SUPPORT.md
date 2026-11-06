# Support

## Where to ask

| Question | Where |
|---|---|
| "How do I configure X?" | [Wiki](https://github.com/paulmann/PHP-Shield/wiki) first — the configuration reference answers most of it |
| "Is this a bug?" | [Open an issue](https://github.com/paulmann/PHP-Shield/issues/new/choose) with the bug report form |
| "Could you add a rule / provider / backend?" | [Feature request](https://github.com/paulmann/PHP-Shield/issues/new/choose) |
| "This is a vulnerability" | **Not** a public issue — see [SECURITY.md](SECURITY.md) |
| "My site is broken right now" | Not a support channel for this library: a security library that blocks a request is behaving as configured. Switch to `monitor` mode and read the incident journal |

## What makes an answer possible

Include in every report:

- PHP version, `ext-*` available, MySQL/Redis version;
- the shield version (`composer show paulmann/php-shield`);
- `mode`, the relevant configuration keys with secrets removed;
- the decision array you got (`blocked`, `status`, `reason`, `detail`, `score`, `findings`);
- the request that produced it, with the payload reduced to the part that triggers the rule.

## What is out of scope

- tuning detection for a specific application — the library ships conservative defaults, the tuning is yours (see the wiki);
- recovering a database or a server that the library does not manage;
- third-party services (AbuseIPDB.com, AbuseIPDB.ru): quota, keys and account questions belong to them.

## Response expectations

This is a maintained open-source project, not a commercial support contract. Security reports are
answered first (three working days), everything else as time allows.
