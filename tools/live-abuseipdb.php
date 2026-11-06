<?php
/**
 * Live smoke test for the AbuseIPDB integration.
 *
 * Usage:
 *   ABUSEIPDB_API_KEY=... php tools/live-abuseipdb.php [ip] [--provider=com|ru]
 *
 * Prints the parsed reputation, never the key. Exit code 0 = the provider
 * answered, 1 = no answer (network, auth, quota).
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use Deynekin\PhpShield\ThreatIntel\CurlTransport;
use Deynekin\PhpShield\ThreatIntel\IpReputation;

$ip = '8.8.8.8';
$providerName = 'com';

foreach (array_slice($argv, 1) as $argument) {
    if (str_starts_with($argument, '--provider=')) {
        $providerName = substr($argument, strlen('--provider='));
        continue;
    }

    $ip = $argument;
}

$key = getenv($providerName === 'ru' ? 'ABUSEIPDB_RU_API_KEY' : 'ABUSEIPDB_API_KEY');

if (!is_string($key) || $key === '') {
    fwrite(STDERR, "Set ABUSEIPDB_API_KEY (or ABUSEIPDB_RU_API_KEY) first.\n");
    exit(1);
}

$provider = $providerName === 'ru'
    ? AbuseIpDbProvider::ru(new CurlTransport(), $key)
    : AbuseIpDbProvider::com(new CurlTransport(), $key);

try {
    $reputation = $provider->lookup($ip);
} catch (ThreatIntelException $exception) {
    fwrite(STDERR, 'provider error: ' . $exception->getMessage() . "\n");
    exit(1);
}

if (!$reputation instanceof IpReputation) {
    echo "no opinion for {$ip}\n";
    exit(1);
}

printf(
    "%s: ip=%s score=%d whitelisted=%s reports=%d distinct=%d country=%s isp=%s usage=%s last=%s\n",
    $reputation->provider,
    $reputation->ip,
    $reputation->abuseConfidenceScore,
    $reputation->isWhitelisted ? 'yes' : 'no',
    $reputation->totalReports,
    $reputation->distinctUsers,
    $reputation->countryCode,
    $reputation->isp,
    $reputation->usageType,
    $reputation->lastReportedAt
);

exit(0);
