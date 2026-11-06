# Integration reference: AbuseIPDB.RU platform

This directory holds the reference adapter used to replace the hand-written
`Iya\Security\Protect\SecurityMiddleware` of the AbuseIPDB.RU site with this
package. The site keeps its own database schema (`security_ip_blocks`,
`security_incidents`, `security_failed_attempts`, migration 033), so the only
project-specific part is the storage mapping — no data migration.

| File | Goes to | Purpose |
|---|---|---|
| `DbBlockStore.php` | `src/Security/Protect/DbBlockStore.php` | maps `BlockStoreInterface` (+ failed attempts, maintenance) onto the site tables |
| `SecurityMiddleware.php` | `src/Security/Protect/SecurityMiddleware.php` | thin adapter extending the package middleware, same public API as before |
| `site-integration-test.php` | keep anywhere | end-to-end check against a copy of the site database |

## Install

1. Vendor the library next to the existing `lib/form-spam-checker`:

   ```powershell
   New-Item -ItemType Directory -Force -Path lib\php-shield\src
   Copy-Item <path-to-PHP-Shield>\src\* lib\php-shield\src -Recurse -Force
   Copy-Item <path-to-PHP-Shield>\LICENSE lib\php-shield\LICENSE
   ```

2. Register the namespace in `bootstrap/autoload.php` (before the
   `FormSpamChecker` entry):

   ```php
   'Deynekin\\PhpShield\\' => $root . '/lib/php-shield/src/',
   ```

3. Back up and replace the old class:

   ```powershell
   Copy-Item src\Security\Protect\SecurityMiddleware.php `
             src\Security\Protect\SecurityMiddleware.php.bak-20261107-php-shield
   Copy-Item ..\integration\abuseipdb-ru\DbBlockStore.php      src\Security\Protect\DbBlockStore.php
   Copy-Item ..\integration\abuseipdb-ru\SecurityMiddleware.php src\Security\Protect\SecurityMiddleware.php
   ```

4. Verify:

   ```powershell
   php -l src\Security\Protect\SecurityMiddleware.php
   php -l src\Security\Protect\DbBlockStore.php
   pwsh -NoProfile -File tools\smoke-local.ps1          # expects 7/7 PASS
   php integration\abuseipdb-ru\site-integration-test.php <copy-of-var\data\iya.sqlite3>
   ```

## Public API preserved

`Shield.php`, `Http\Kernel` and `Core\Config` keep working unchanged:

```php
$middleware->isIpBlocked($ip);
$middleware->blockIp($ip, $reason, SecurityMiddleware::SEVERITY_MEDIUM);
$middleware->recordIncident($ip, 'waf_blocked', $text, SecurityMiddleware::SEVERITY_HIGH, $context);
$middleware->recentIncidentCount($ip, 600);
$middleware->unblockIp($ip);
```

Durations are identical to the replaced class: critical 12 h, high 4 h,
medium 1 h, low 30 min (`severity_block_multipliers`).

## Rollback

```powershell
Move-Item -Force src\Security\Protect\SecurityMiddleware.php.bak-20261107-php-shield `
                src\Security\Protect\SecurityMiddleware.php
Remove-Item src\Security\Protect\DbBlockStore.php
# bootstrap/autoload.php.bak-20261107-php-shield → bootstrap/autoload.php
```

## Verified on 2026-11-07

- `tools/verify-package.ps1` — 8/9, the only non-pass is `git-clean` (the working tree is intentionally modified).
- `tools/smoke-local.ps1` — **7/7 PASS** against the real site.
- `site-integration-test.php` — 15/15 checks on a copy of `var/data/iya.sqlite3`
  (incidents, temporary block with kind/severity/expiry, unblock, failed
  attempts, statistics, trusted address).
- Found and fixed during the swap: the package middleware was `final`, so the
  adapter could not extend it — the site's own smoke test surfaced a fatal error
  on the first run.
