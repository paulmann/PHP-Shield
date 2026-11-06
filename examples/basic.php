<?php
/**
 * Basic usage: create the shield, inspect a request, act on the decision.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\ShieldFactory;

$config = require __DIR__ . '/../config/default.php';
$config['mode'] = 'monitor'; // start safe; switch to 'block' after reviewing the incidents

$mysqli = new mysqli('127.0.0.1', 'root', '', 'php_shield');

$shield = ShieldFactory::create($config, $mysqli);

$decision = $shield->inspect(
    array_merge($_GET, $_POST),
    $_SERVER,
    $_SERVER['REQUEST_URI'] ?? '/'
);

if ($decision['blocked']) {
    http_response_code($decision['status']);
    header('Content-Type: application/json');
    echo json_encode(['error' => $decision['reason'], 'detail' => $decision['detail']]);
    exit;
}

echo "Request allowed (score {$decision['score']})\n";
