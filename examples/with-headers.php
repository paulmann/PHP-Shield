<?php
/**
 * Example: send security headers, then run the shield.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\Middleware\Shield;
use Deynekin\PhpShield\ShieldFactory;
use Deynekin\PhpShield\Support\SecurityHeaders;

SecurityHeaders::send([
    'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'",
    // Only once the site is HTTPS-only:
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
]);

$config = require __DIR__ . '/../config/default.php';

$mysqli = new mysqli('127.0.0.1', 'root', '', 'php_shield');
$shield = ShieldFactory::create($config, $mysqli);

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER);

if ($decision['blocked']) {
    http_response_code($decision['status']);
    exit("Blocked: {$decision['reason']}\n");
}

echo 'Headers sent, request allowed by ' . Shield::class . "\n";
