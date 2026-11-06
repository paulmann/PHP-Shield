<?php
/**
 * Example: IP reputation through AbuseIPDB.com with AbuseIPDB.ru as fallback.
 *
 * Keys are read from the environment; never hard-code them.
 *
 *   export ABUSEIPDB_API_KEY=...
 *   export ABUSEIPDB_RU_API_KEY=...
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\ShieldFactory;

$config = require __DIR__ . '/../config/default.php';

$config['ip_reputation']['enabled'] = true;
$config['ip_reputation']['block_score'] = 75; // block from this abuseConfidenceScore
$config['ip_reputation']['flag_score'] = 25;  // only journal from here

// The two providers share the API v2 contract; the order is the fallback order.
$config['ip_reputation']['providers'] = [
    [
        'name' => 'abuseipdb.com',
        'base_url' => 'https://api.abuseipdb.com/api/v2',
        'api_key' => null,
        'api_key_env' => 'ABUSEIPDB_API_KEY',
    ],
    [
        'name' => 'abuseipdb.ru',
        'base_url' => 'https://abuseipdb.ru/api/v2',
        'api_key' => null,
        'api_key_env' => 'ABUSEIPDB_RU_API_KEY',
    ],
];

$mysqli = new mysqli('127.0.0.1', 'root', '', 'php_shield');
$shield = ShieldFactory::create($config, $mysqli);

// A request from an address with a bad reputation is blocked in 'block' mode and
// journaled in 'monitor' mode — the same call either way.
$decision = $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

if ($decision['blocked']) {
    http_response_code($decision['status']);
    exit("Blocked: {$decision['reason']} (score {$decision['score']})\n");
}

echo "Allowed (score {$decision['score']})\n";
