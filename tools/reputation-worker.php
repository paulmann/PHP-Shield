<?php
/**
 * Reputation worker: fills the IP reputation cache out of band.
 *
 * The request path never calls AbuseIPDB — it only queues unknown addresses.
 * Run this worker from cron every minute:
 *
 *   * * * * * php /path/to/PHP-Shield/tools/reputation-worker.php
 *
 * Options:
 *   --status        print the queue size and exit
 *   --ip=1.2.3.4    look one address up now (debugging)
 *   --limit=N       override ip_reputation.per_run for this run
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\ShieldFactory;

$configFile = getenv('PHP_SHIELD_CONFIG');
$configPath = is_string($configFile) && $configFile !== '' ? $configFile : __DIR__ . '/../config/default.php';

$config = is_file($configPath) ? require $configPath : [];

if (!is_array($config)) {
    $config = [];
}

$singleIp = null;
$limitOverride = null;
$statusOnly = false;

foreach (array_slice($argv, 1) as $argument) {
    if ($argument === '--status') {
        $statusOnly = true;

        continue;
    }

    if (str_starts_with($argument, '--ip=')) {
        $singleIp = substr($argument, strlen('--ip='));

        continue;
    }

    if (str_starts_with($argument, '--limit=')) {
        $value = substr($argument, strlen('--limit='));
        $limitOverride = is_numeric($value) ? (int) $value : null;
    }
}

if (!class_exists(mysqli::class)) {
    fwrite(STDERR, "The mysqli extension is required for the reputation worker.\n");
    exit(2);
}

$dbHost = getenv('DB_HOST');
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');
$dbName = getenv('DB_NAME');

try {
    $mysqli = new mysqli(
        is_string($dbHost) && $dbHost !== '' ? $dbHost : '127.0.0.1',
        is_string($dbUser) && $dbUser !== '' ? $dbUser : 'root',
        is_string($dbPass) ? $dbPass : '',
        is_string($dbName) && $dbName !== '' ? $dbName : 'php_shield'
    );
} catch (mysqli_sql_exception $exception) {
    fwrite(STDERR, 'Database connection failed (error code ' . $exception->getCode() . ").\n");
    exit(2);
}

$checker = ShieldFactory::createReputationChecker($config, $mysqli);

if ($checker === null) {
    fwrite(STDERR, "IP reputation is disabled or has no API key: nothing to do.\n");
    exit(1);
}

if (!$checker->isAsync()) {
    fwrite(STDERR, "ip_reputation.mode is 'sync': lookups happen inline, the queue is unused.\n");
    exit(1);
}

if ($statusOnly) {
    printf("queue=%d providers=%s mode=async\n", $checker->queueSize(), implode(',', $checker->providerNames()));
    exit(0);
}

if (is_string($singleIp) && $singleIp !== '') {
    try {
        $reputation = $checker->fetch($singleIp);
    } catch (ThreatIntelException $exception) {
        fwrite(STDERR, 'lookup failed: ' . $exception->getMessage() . "\n");
        exit(3);
    }

    if ($reputation === null) {
        echo "no opinion for {$singleIp}\n";
        exit(0);
    }

    printf(
        "%s: ip=%s score=%d whitelisted=%s reports=%d\n",
        $reputation->provider,
        $reputation->ip,
        $reputation->abuseConfidenceScore,
        $reputation->isWhitelisted ? 'yes' : 'no',
        $reputation->totalReports
    );
    exit(0);
}

$worker = ShieldFactory::createReputationWorker($config, $mysqli);

if ($worker === null) {
    fwrite(STDERR, "Worker is not available for the current configuration.\n");
    exit(1);
}

$stats = $worker->drain();

printf(
    "processed=%d fetched=%d empty=%d failed=%d skipped=%d queued=%d\n",
    $stats['processed'],
    $stats['fetched'],
    $stats['empty'],
    $stats['failed'],
    $stats['skipped'],
    $stats['queued']
);

exit(0);
