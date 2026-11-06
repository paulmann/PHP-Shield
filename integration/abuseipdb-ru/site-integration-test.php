<?php
/**
 * End-to-end check of the PHP Shield integration inside the AbuseIPDB.RU site.
 *
 * Runs against a temporary copy of the site database, so the original stays
 * byte-identical and the repository checksum keeps matching.
 *
 *   php integration/abuseipdb-ru/site-integration-test.php <sqlite-copy>
 */

declare(strict_types=1);

$site = 'C:/AutoClaw/AbuseIPDB.ru/src';
$database = $argv[1] ?? '';

if ($database === '' || !is_file($database)) {
    fwrite(STDERR, "usage: php site-integration-test.php <sqlite-copy>\n");
    exit(2);
}

require $site . '/bootstrap/autoload.php';

use Iya\Infrastructure\Db\Db;
use Iya\Security\Protect\SecurityMiddleware;

$pdo = new PDO('sqlite:' . $database, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$db = new Db($pdo, 'sqlite');
$middleware = new SecurityMiddleware($db, null, ['trusted_ips' => ['127.0.0.1']]);

$ip = '203.0.113.99';
$failures = 0;

function check(string $label, mixed $actual, mixed $expected): void
{
    global $failures;

    $ok = $actual === $expected;

    if (!$ok) {
        $failures++;
    }

    printf("%s %s (got %s, expected %s)\n", $ok ? 'PASS' : 'FAIL', $label, var_export($actual, true), var_export($expected, true));
}

// Clean up any residue from an earlier run.
$db->execute('DELETE FROM security_incidents WHERE ip = ?', [$ip]);
$db->execute('DELETE FROM security_ip_blocks WHERE ip = ?', [$ip]);
$db->execute('DELETE FROM security_failed_attempts WHERE ip = ?', [$ip]);

check('store is the PHP Shield one', $middleware instanceof \Deynekin\PhpShield\Middleware\SecurityMiddleware, true);

// Incidents -----------------------------------------------------------------
$middleware->recordIncident($ip, 'integration_test', 'PHP Shield integration check', SecurityMiddleware::SEVERITY_HIGH, ['score' => 90]);
check('incident recorded', $middleware->recentIncidentCount($ip, 600), 1);
check('recent incidents readable', count($middleware->recentIncidents(5)) > 0, true);

// Blocks --------------------------------------------------------------------
check('not blocked initially', $middleware->isIpBlocked($ip), false);

$middleware->blockIp($ip, 'integration check', SecurityMiddleware::SEVERITY_MEDIUM);
check('temporary block applied', $middleware->isIpBlocked($ip), true);

$row = $db->fetch('SELECT kind, severity, blocked_until FROM security_ip_blocks WHERE ip = ?', [$ip]);
check('block row kind', $row['kind'] ?? null, 'temporary');
check('block row severity', $row['severity'] ?? null, 'medium');
check('block row has expiry', is_string($row['blocked_until'] ?? null), true);

$middleware->unblockIp($ip);
check('unblocked', $middleware->isIpBlocked($ip), false);

// Failed attempts -----------------------------------------------------------
check('failed attempt counted', $middleware->recordFailedAttempt($ip), 1);
check('failed attempt visible', $middleware->failedAttempts($ip), 1);
$middleware->clearFailedAttempts($ip);
check('failed attempts cleared', $middleware->failedAttempts($ip), 0);

// Statistics ----------------------------------------------------------------
$stats = $middleware->stats();
check('stats expose totals', is_int($stats['incidents_total'] ?? null), true);
check('stats expose breakdown', is_array($stats['by_type'] ?? null), true);

// Trusted address is never blocked ------------------------------------------
$middleware->blockIp('127.0.0.1', 'must be ignored');
check('trusted address stays unblocked', $middleware->isIpBlocked('127.0.0.1'), false);

// Clean up the rows this script created.
$db->execute('DELETE FROM security_incidents WHERE ip = ?', [$ip]);
$db->execute('DELETE FROM security_ip_blocks WHERE ip = ?', [$ip]);
$db->execute('DELETE FROM security_failed_attempts WHERE ip = ?', [$ip]);

echo $failures === 0 ? "\nSITE INTEGRATION: ALL CHECKS PASSED\n" : "\nSITE INTEGRATION: {$failures} CHECK(S) FAILED\n";

exit($failures === 0 ? 0 : 1);
