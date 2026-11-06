<?php

/**
 * Reference replacement for the hand-written middleware of AbuseIPDB.RU.
 *
 * Before: a 400-line class that owned the SQL, the block policy and the
 * incident journal, and was copied between projects.
 * After: this thin adapter — the policy now lives in the PHP Shield package and
 * only the storage mapping is project-specific (DbBlockStore).
 *
 * The public API is preserved, so `Iya\Security\Protect\Shield`,
 * `Http\Kernel` and `Core\Config` keep working without changes:
 *
 *   $middleware->isIpBlocked($ip)
 *   $middleware->blockIp($ip, $reason, SecurityMiddleware::SEVERITY_MEDIUM)
 *   $middleware->recordIncident($ip, 'waf_blocked', $text, SecurityMiddleware::SEVERITY_HIGH, $context)
 *   $middleware->recentIncidentCount($ip, 600)
 *
 * Copy it into the project as `src/Security/Protect/SecurityMiddleware.php`.
 */

declare(strict_types=1);

namespace Iya\Security\Protect;

use Deynekin\PhpShield\Middleware\SecurityMiddleware as ShieldMiddleware;
use Iya\Infrastructure\Db\Db;
use Iya\Infrastructure\Log\Logger;

final class SecurityMiddleware extends ShieldMiddleware
{
    /** Kept for call sites that still reference the old constant. */
    public const SEVERITY_INFO = 'info';

    public function __construct(Db $db, ?Logger $logger = null, array $config = [])
    {
        parent::__construct(new DbBlockStore($db, $logger), $config);
    }
}
