<?php
/**
 * MySQL self-test: exercises the real storage classes against a live database.
 *
 * Usage:
 *   MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php [database]
 *
 * The script creates its own schema objects (auto-migrate) inside the given
 * database and only touches rows it created itself. It never drops a database.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\Middleware\SecurityMiddleware;
use Deynekin\PhpShield\RateLimiting\DatabaseRateLimiter;
use Deynekin\PhpShield\Storage\MysqlBlockStore;
use Deynekin\PhpShield\ThreatIntel\IpReputation;
use Deynekin\PhpShield\ThreatIntel\MysqlReputationCache;
use Deynekin\PhpShield\ThreatIntel\MysqlReputationQueue;

if (!extension_loaded('mysqli')) {
    fwrite(STDERR, "mysqli is not loaded: run with -d extension=php_mysqli\n");
    exit(2);
}

$database = $argv[1] ?? 'php_shield_test';
$password = getenv('MYSQL_PWD');
$host = getenv('MYSQL_HOST') ?: '127.0.0.1';

$mysqli = @new mysqli($host, 'root', is_string($password) ? $password : '', $database);

if ($mysqli->connect_errno !== 0) {
    fwrite(STDERR, 'connect failed: error code ' . $mysqli->connect_errno . "\n");
    exit(2);
}

$failures = 0;

/**
 * @param mixed $actual
 * @param mixed $expected
 */
function check(string $label, $actual, $expected): void
{
    global $failures;

    $ok = $actual === $expected;

    if (!$ok) {
        $failures++;
    }

    printf("%s %s (got %s, expected %s)\n", $ok ? 'PASS' : 'FAIL', $label, var_export($actual, true), var_export($expected, true));
}

$store = new MysqlBlockStore($mysqli);
$ip = '203.0.113.77';

// Blocks -------------------------------------------------------------------
$store->unblock($ip);
check('not blocked initially', $store->isBlocked($ip), false);

$store->block($ip, 'selftest temporary', 60, 'temporary', 'high');
check('temporary block visible', $store->isBlocked($ip), true);
check('temporary is not permanent', $store->isPermanentlyBlocked($ip), false);

$severity = $mysqli->query("SELECT severity FROM php_shield_ip_blocks WHERE ip_address = '{$ip}'")->fetch_assoc()['severity'] ?? null;
check('severity stored', $severity, 'high');

$store->block($ip, 'selftest permanent', null, 'permanent', 'critical');
check('permanent block visible', $store->isPermanentlyBlocked($ip), true);

$active = $store->getActiveBlocks(10);
check('active blocks listed', count($active) > 0, true);

$store->unblock($ip);
check('unblocked', $store->isBlocked($ip), false);

// Incidents ----------------------------------------------------------------
$before = $store->countIncidents($ip, 3600);
$store->logIncident($ip, null, 'selftest', 'selftest incident', 'high', ['payload' => "\xB1\x31 invalid utf8"]);
check('incident counted', $store->countIncidents($ip, 3600), $before + 1);

$recent = $store->getRecentIncidents(5);
check('recent incidents readable', is_array($recent) && $recent !== [], true);

$stats = $store->getStats();
check('stats have totals', is_int($stats['incidents_total'] ?? null), true);
check('stats have breakdown', is_array($stats['by_type'] ?? null), true);

// Failed attempts ----------------------------------------------------------
$store->clearFailedAttempts($ip);
$store->recordFailedAttempt($ip);
check('failed attempt counted', $store->recordFailedAttempt($ip), 2);
$store->clearFailedAttempts($ip);
check('failed attempts cleared', $store->getFailedAttempts($ip), 0);

// Middleware over the real store -------------------------------------------
$middleware = new SecurityMiddleware($store, ['trusted_ips' => [], 'block_duration' => 60]);
$middleware->blockIp($ip, 'selftest middleware', SecurityMiddleware::SEVERITY_HIGH);
check('middleware blocks', $middleware->isIpBlocked($ip), true);
$middleware->unblockIp($ip);

// Rate limiter -------------------------------------------------------------
$limiter = new DatabaseRateLimiter($mysqli);
$key = 'selftest:' . bin2hex(random_bytes(4));
$allowed = 0;

for ($i = 0; $i < 5; $i++) {
    if ($limiter->allow($key, 3, 60)) {
        $allowed++;
    }
}

check('rate limiter allows exactly the limit', $allowed, 3);
check('remaining is zero', $limiter->getRemaining($key, 3, 60), 0);
check('prune runs', is_int($limiter->prune(3600)), true);

// Reputation cache ---------------------------------------------------------
$cache = new MysqlReputationCache($mysqli);
$reputation = new IpReputation(
    ip: '203.0.113.77',
    provider: 'abuseipdb.com',
    abuseConfidenceScore: 88,
    isWhitelisted: false,
    totalReports: 5,
    distinctUsers: 3,
    countryCode: 'RU',
    isp: 'Selftest ISP',
    usageType: 'Data Center',
    lastReportedAt: '2026-11-07T00:00:00+00:00',
    fetchedAt: time()
);

$cache->set('selftest:reputation', $reputation->toArray(), 60);
$cached = $cache->get('selftest:reputation');
check('reputation cache round-trip', is_array($cached) ? ($cached['score'] ?? null) : null, 88);
check('reputation rebuild', IpReputation::fromArray(is_array($cached) ? $cached : [])?->isp, 'Selftest ISP');

// Reputation queue (async mode) ---------------------------------------------
$queue = new MysqlReputationQueue($mysqli);
$queue->complete($ip);
$queue->push($ip);
check('queue accepts an address', $queue->size(), 1);
$queue->push($ip);
check('queue deduplicates', $queue->size(), 1);
check('queue claims the address', in_array($ip, $queue->claim(5), true), true);
$queue->fail($ip, 'selftest failure', 60);
check('failed address stays queued', $queue->size(), 1);
check('failed address is not due yet', in_array($ip, $queue->claim(5), true), false);
$mysqli->query("UPDATE php_shield_reputation_queue SET next_attempt_at = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE ip_address = '{$ip}'");
check('backoff expires', in_array($ip, $queue->claim(5), true), true);
$queue->complete($ip);
check('completed address leaves the queue', $queue->size(), 0);

// Cleanup ------------------------------------------------------------------
$cleanup = $store->cleanup(30);
check('cleanup returns counters', array_keys($cleanup), ['blocks', 'incidents', 'attempts']);

$tables = [];
$result = $mysqli->query('SHOW TABLES');
while (is_array($row = $result->fetch_array(MYSQLI_NUM))) {
    $tables[] = (string) $row[0];
}

check('all tables present', count(array_intersect(
    ['php_shield_ip_blocks', 'php_shield_incidents', 'php_shield_failed_attempts', 'php_shield_rate_limit', 'php_shield_ip_reputation', 'php_shield_reputation_queue'],
    $tables
)), 6);

$mysqli->close();

echo $failures === 0 ? "\nALL DB CHECKS PASSED\n" : "\n{$failures} DB CHECK(S) FAILED\n";

exit($failures === 0 ? 0 : 1);
