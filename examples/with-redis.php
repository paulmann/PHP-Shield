<?php
/**
 * Example using the Redis rate limiter (recommended for concurrent traffic).
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Deynekin\PhpShield\Ip\IpResolver;
use Deynekin\PhpShield\Middleware\SecurityMiddleware;
use Deynekin\PhpShield\Middleware\Shield;
use Deynekin\PhpShield\RateLimiting\RedisRateLimiter;
use Deynekin\PhpShield\Storage\MysqlBlockStore;

$config = require __DIR__ . '/../config/default.php';
$config['rate_limiter'] = 'redis';

$mysqli = new mysqli(
    getenv('DB_HOST') ?: '127.0.0.1',
    getenv('DB_USER') ?: 'root',
    getenv('DB_PASS') ?: '',
    getenv('DB_NAME') ?: 'php_shield'
);

$redis = new Redis();
$redis->connect($config['redis']['host'], $config['redis']['port']);

if (!empty($config['redis']['password'])) {
    $redis->auth($config['redis']['password']);
}

$redis->select((int) $config['redis']['database']);

$shield = new Shield(
    new SecurityMiddleware(new MysqlBlockStore($mysqli), $config),
    new RedisRateLimiter($redis, $config['redis']['prefix']),
    new IpResolver($config['trusted_proxies']),
    $config
);

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER);

if ($decision['blocked']) {
    http_response_code($decision['status']);

    if ($decision['status'] === 429) {
        header('Retry-After: 60');
    }

    exit("Blocked: {$decision['reason']}\n");
}

echo "Request allowed (Redis rate limiter)\n";
