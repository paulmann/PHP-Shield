<?php
/**
 * PHP-Shield Admin Interface
 *
 * Every state changing POST is protected by a per-session anti-CSRF token.
 * Protect this endpoint further at the web-server level (IP allowlist, VPN,
 * HTTP authentication): the login form is only as strong as its password.
 */

declare(strict_types=1);

use Deynekin\PhpShield\Admin\AdminAccess;
use Deynekin\PhpShield\Admin\AdminDashboard;
use Deynekin\PhpShield\Storage\MysqlBlockStore;
use Deynekin\PhpShield\Support\SecurityHeaders;

require_once __DIR__ . '/../../vendor/autoload.php';

SecurityHeaders::send([
    'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
]);

$configFile = __DIR__ . '/../../config/default.php';
$override = getenv('PHP_SHIELD_CONFIG');

if (is_string($override) && $override !== '' && is_file($override)) {
    $configFile = $override;
}

$config = is_file($configFile) ? require $configFile : [];

if (!is_array($config)) {
    $config = [];
}

// IP allowlist (admin.allowed_ips). Empty list = disabled. Checked before the
// database is touched, so a stranger cannot even open a connection.
$access = new AdminAccess($config);

if (!$access->allowsRequest($_SERVER)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Forbidden.');
}

if (!class_exists(mysqli::class)) {
    http_response_code(500);
    exit('The mysqli extension is required for the admin dashboard.');
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
    error_log('PHP-Shield admin: database connection failed: ' . $exception->getMessage());
    http_response_code(500);
    exit('Database connection failed.');
}

$dashboard = new AdminDashboard(new MysqlBlockStore($mysqli), $config);

$path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
$self = is_string($path) && $path !== '' ? $path : './';

$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
$action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
$token = isset($_POST['csrf_token']) && is_string($_POST['csrf_token']) ? $_POST['csrf_token'] : null;

$error = '';
$notice = '';

$messages = [
    'blocked' => 'The address has been blocked.',
    'unblocked' => 'The address has been unblocked.',
    'invalid-ip' => 'That is not a valid IP address.',
];

$messageCode = isset($_GET['msg']) && is_string($_GET['msg']) ? $_GET['msg'] : '';
$notice = $messages[$messageCode] ?? '';

if ($method === 'POST' && $action !== '') {
    if ($action === 'login') {
        $username = isset($_POST['username']) && is_string($_POST['username']) ? $_POST['username'] : '';
        $password = isset($_POST['password']) && is_string($_POST['password']) ? $_POST['password'] : '';
        $lockout = $dashboard->getLockoutRemaining();

        if ($lockout > 0) {
            http_response_code(429);
            $error = "Too many failed attempts. Try again in {$lockout} seconds.";
        } elseif ($dashboard->authenticate($username, $password)) {
            header('Location: ' . $self, true, 303);
            exit;
        } else {
            http_response_code(401);
            $error = 'Invalid credentials.';
        }
    } elseif (!$dashboard->validateCsrfToken($token)) {
        http_response_code(400);
        $error = 'Invalid or expired form token. Reload the page and try again.';
    } elseif ($action === 'logout') {
        $dashboard->logout();
        header('Location: ' . $self, true, 303);
        exit;
    } elseif ($action === 'block' || $action === 'unblock') {
        $ip = isset($_POST['ip']) && is_string($_POST['ip']) ? $_POST['ip'] : '';

        if ($action === 'unblock') {
            $done = $dashboard->unblockIp($ip);
        } else {
            $reason = isset($_POST['reason']) && is_string($_POST['reason']) ? $_POST['reason'] : 'Manual block';
            $duration = isset($_POST['duration']) ? (int) $_POST['duration'] : 3600;
            $type = isset($_POST['type']) && is_string($_POST['type']) ? $_POST['type'] : 'temporary';
            $done = $dashboard->blockIp($ip, $reason, $duration, $type);
        }

        $result = $done ? ($action === 'block' ? 'blocked' : 'unblocked') : 'invalid-ip';
        header('Location: ' . $self . '?msg=' . $result, true, 303);
        exit;
    }
}

$authenticated = $dashboard->isAuthenticated();
$stats = $authenticated ? $dashboard->getStats() : [];
$blocks = $authenticated ? $dashboard->getActiveBlocks() : [];
$csrf = $dashboard->csrfToken();

$esc = static function (string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>PHP-Shield Admin</title>
    <style>
        :root { --bg: #f7fafc; --card: #fff; --primary: #2b6cb0; --danger: #c53030; }
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: var(--bg); color: #1a202c; }
        .container { max-width: 1200px; margin: 2rem auto; background: var(--card); padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,.08); }
        h1 { color: #1a365d; margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: .75rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #edf2f7; font-weight: 600; }
        .btn { padding: .5rem 1rem; border: none; border-radius: 6px; cursor: pointer; font-size: .9rem; }
        .btn-danger { background: var(--danger); color: #fff; }
        .btn-primary { background: var(--primary); color: #fff; }
        .btn-secondary { background: #718096; color: #fff; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
        .stat { background: #ebf8ff; padding: 1rem; border-radius: 8px; }
        .stat strong { display: block; font-size: .85rem; color: #2c5282; }
        .stat span { font-size: 1.4rem; font-weight: 700; }
        form.inline { display: inline; }
        input, select { padding: .45rem .6rem; border: 1px solid #cbd5e0; border-radius: 4px; }
        .manual-block { background: #f7fafc; padding: 1rem; border-radius: 8px; margin: 1.5rem 0; }
        pre { background: #1a202c; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow: auto; font-size: .85rem; }
        .alert { padding: .75rem 1rem; border-radius: 8px; margin: 1rem 0; }
        .alert-error { background: #fff5f5; color: #9b2c2c; border: 1px solid #feb2b2; }
        .alert-notice { background: #f0fff4; color: #22543d; border: 1px solid #9ae6b4; }
    </style>
</head>
<body>
<div class="container">
    <h1>PHP-Shield Admin Dashboard</h1>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?= $esc($error) ?></div>
    <?php endif; ?>
    <?php if ($notice !== ''): ?>
        <div class="alert alert-notice"><?= $esc($notice) ?></div>
    <?php endif; ?>

    <?php if (!$authenticated): ?>
        <h2>Login</h2>
        <form method="post">
            <input type="hidden" name="action" value="login">
            <input type="hidden" name="csrf_token" value="<?= $esc($csrf) ?>">
            <input type="text" name="username" placeholder="Username" required autofocus autocomplete="username">
            <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
            <button class="btn btn-primary" type="submit">Login</button>
        </form>
        <p><small>Set <code>admin.password_hash</code> in config. Generate with:<br>
            <code>php -r "echo password_hash('your-secret', PASSWORD_DEFAULT);"</code></small></p>
    <?php else: ?>
        <form method="post" style="float:right">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf_token" value="<?= $esc($csrf) ?>">
            <button class="btn btn-secondary" type="submit">Logout</button>
        </form>

        <div class="stats">
            <div class="stat"><strong>Active Blocks</strong><span><?= (int) ($stats['active_blocks'] ?? 0) ?></span></div>
            <div class="stat"><strong>Permanent</strong><span><?= (int) ($stats['permanent_blocks'] ?? 0) ?></span></div>
            <div class="stat"><strong>Incidents (24h)</strong><span><?= (int) ($stats['incidents_24h'] ?? 0) ?></span></div>
            <div class="stat"><strong>High Severity (7d)</strong><span><?= (int) ($stats['high_severity_7d'] ?? 0) ?></span></div>
            <div class="stat"><strong>Mode</strong><span><?= $esc((string) ($stats['mode'] ?? 'monitor')) ?></span></div>
            <div class="stat"><strong>Rate Limiter</strong><span><?= $esc((string) ($stats['rate_limiter'] ?? 'database')) ?></span></div>
        </div>

        <div class="manual-block">
            <h3>Manual Block</h3>
            <form method="post">
                <input type="hidden" name="action" value="block">
                <input type="hidden" name="csrf_token" value="<?= $esc($csrf) ?>">
                <input type="text" name="ip" placeholder="IP address" required pattern="^[0-9a-fA-F:.]+$">
                <input type="text" name="reason" placeholder="Reason" value="Manual block">
                <input type="number" name="duration" value="3600" min="0" style="width:100px"> sec
                <select name="type">
                    <option value="temporary">Temporary</option>
                    <option value="permanent">Permanent</option>
                </select>
                <button class="btn btn-danger" type="submit">Block</button>
            </form>
        </div>

        <h2>Active IP Blocks</h2>
        <?php if ($blocks === []): ?>
            <p>No active blocks.</p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Type</th>
                        <th>Reason</th>
                        <th>Expires</th>
                        <th>Created</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($blocks as $block): ?>
                        <?php
                        $rowIp = is_string($block['ip_address'] ?? null) ? $block['ip_address'] : '';
                        $rowType = is_string($block['block_type'] ?? null) ? $block['block_type'] : '';
                        $rowReason = is_string($block['reason'] ?? null) ? $block['reason'] : '';
                        $rowExpires = is_string($block['expires_at'] ?? null) ? $block['expires_at'] : 'Never';
                        $rowCreated = is_string($block['created_at'] ?? null) ? $block['created_at'] : '';
                        ?>
                        <tr>
                            <td><code><?= $esc($rowIp) ?></code></td>
                            <td><?= $esc($rowType) ?></td>
                            <td><?= $esc($rowReason) ?></td>
                            <td><?= $esc($rowExpires) ?></td>
                            <td><?= $esc($rowCreated) ?></td>
                            <td>
                                <form method="post" class="inline">
                                    <input type="hidden" name="action" value="unblock">
                                    <input type="hidden" name="csrf_token" value="<?= $esc($csrf) ?>">
                                    <input type="hidden" name="ip" value="<?= $esc($rowIp) ?>">
                                    <button class="btn btn-danger" type="submit">Unblock</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <h2>Current Configuration</h2>
        <p><small>Credentials are masked. Edit <code>config/default.php</code> to change values.</small></p>
        <pre><?= $esc((string) json_encode($dashboard->getSafeConfig(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)) ?></pre>
    <?php endif; ?>
</div>
</body>
</html>
