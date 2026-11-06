# PHP Shield — documentation map

The long-form documentation lives in the [repository wiki](https://github.com/paulmann/PHP-Shield/wiki)
and is maintained as Markdown in `wiki/` — one source, built and published by `ghagent wiki build`
and `ghagent wiki publish`. This page is the map: it says where each answer is written down, so a
reader does not have to grep two copies of the same text.

## Start here

| Question | Page |
|---|---|
| What is this package, what does it not do? | [Home](https://github.com/paulmann/PHP-Shield/wiki) |
| How do I install it and get a first decision? | [Getting started](https://github.com/paulmann/PHP-Shield/wiki/01-Getting-Started) |
| Which configuration key does what? | [Configuration reference](https://github.com/paulmann/PHP-Shield/wiki/02-Configuration) |
| It blocked something it should not have | [Troubleshooting](https://github.com/paulmann/PHP-Shield/wiki/11-Troubleshooting) and [Detection rules](https://github.com/paulmann/PHP-Shield/wiki/03-Detection-Rules) |

## By task

| Task | Page |
|---|---|
| Add or tune a detection rule | [Detection rules](https://github.com/paulmann/PHP-Shield/wiki/03-Detection-Rules) |
| Turn on AbuseIPDB.com / AbuseIPDB.ru reputation | [IP reputation](https://github.com/paulmann/PHP-Shield/wiki/04-IP-Reputation) |
| Understand modes, thresholds and block lifetimes | [Modes and block lifetimes](https://github.com/paulmann/PHP-Shield/wiki/05-Modes-and-Blocks) |
| Read the incident journal, blocks and counters from code | [State and storage](https://github.com/paulmann/PHP-Shield/wiki/06-State-and-Storage) |
| Choose between the database and Redis limiter | [Rate limiting](https://github.com/paulmann/PHP-Shield/wiki/07-Rate-Limiting) |
| Secure or extend the dashboard | [Admin dashboard](https://github.com/paulmann/PHP-Shield/wiki/08-Admin-Dashboard) |
| Run behind nginx / Cloudflare / a load balancer | [Reverse proxies and client IP](https://github.com/paulmann/PHP-Shield/wiki/09-Reverse-Proxies) |
| Prepare a production deploy | [Production checklist](https://github.com/paulmann/PHP-Shield/wiki/10-Production-Checklist) |
| Migrate from SecurityMiddleware 1.x | [Upgrading](https://github.com/paulmann/PHP-Shield/wiki/12-Upgrading) |
| Understand why the code is shaped like this | [Architecture](https://github.com/paulmann/PHP-Shield/wiki/13-Architecture) |
| Know what was found and fixed in the security review | [Security](https://github.com/paulmann/PHP-Shield/wiki/14-Security) |
| Run the tests, the static analysis and the CI jobs | [Development](https://github.com/paulmann/PHP-Shield/wiki/15-Development) |

## In the repository

| File | Content |
|---|---|
| `README.md` | the product page; also translated into `README.ru.md`, `README.de.md`, `README.es.md`, `README.zh.md`, `README.hi.md` |
| `config/default.php` | the annotated configuration — the source of every default quoted in the wiki |
| `migrations/schema.sql` | the production schema |
| `docs/adr.md` | architecture decision records, with the alternatives that were rejected |
| `docs/security-review.md` | the security review: findings, fixes, residual risks |
| `SECURITY.md` | how to report a vulnerability privately |
| `CONTRIBUTING.md` | coding standard, tests, review checklist |
| `AGENTS.md` | instructions for AI coding agents working in this tree |
| `integration/abuseipdb-ru/` | reference adapter and its end-to-end test |

## Keeping the two in sync

`wiki/` is the canonical prose. If a change alters the public API, a configuration default or the
rule table, edit the wiki page and — for the rule table and the quick start — `README.md` as well.
The check is mechanical:

```bash
ghagent wiki build --root .
ghagent wiki verify --root .
ghagent doc --root .
```
