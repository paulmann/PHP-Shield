<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Admin;

use Deynekin\PhpShield\Storage\BlockStoreInterface;
use Deynekin\PhpShield\Support\Config;
use Deynekin\PhpShield\Support\PayloadRedactor;

/**
 * Admin dashboard helper for authentication and management actions.
 *
 * State changing actions must be paired with validateCsrfToken(); the shipped
 * dashboard at public/admin/index.php already does this.
 */
final class AdminDashboard
{
    private const SESSION_AUTH = 'php_shield_admin_authenticated';
    private const SESSION_USER = 'php_shield_admin_user';
    private const SESSION_TIME = 'php_shield_admin_login_time';
    private const SESSION_CSRF = 'php_shield_admin_csrf';
    private const SESSION_FAILURES = 'php_shield_admin_failures';
    private const SESSION_LOCKED = 'php_shield_admin_locked_until';

    private const MAX_FAILURES = 5;
    private const LOCKOUT_SECONDS = 300;
    private const BLOCK_TYPES = ['temporary', 'permanent'];

    private readonly Config $config;

    private readonly SessionInterface $session;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly BlockStoreInterface $blockStore,
        array $config = [],
        ?SessionInterface $session = null
    ) {
        $this->config = Config::fromArray($config);

        if ($session instanceof SessionInterface) {
            $this->session = $session;

            return;
        }

        $options = [
            'name' => $this->config->nestedString('admin.session_name', 'php_shield_admin'),
            'samesite' => $this->config->nestedString('admin.cookie_samesite', 'Strict'),
        ];

        $secure = $this->config->raw('admin.cookie_secure');

        if (is_bool($secure)) {
            $options['secure'] = $secure;
        }

        $this->session = new NativeSession($options);
    }

    public function isAuthenticated(): bool
    {
        if (!$this->adminEnabled() || $this->session->get(self::SESSION_AUTH) !== true) {
            return false;
        }

        $timeout = $this->config->nestedInt('admin.session_timeout', 3600);

        if ($timeout > 0) {
            $startedAt = $this->session->get(self::SESSION_TIME);

            if (!is_int($startedAt) || (time() - $startedAt) > $timeout) {
                $this->logout();

                return false;
            }
        }

        return true;
    }

    public function authenticate(string $username, string $password): bool
    {
        if (!$this->adminEnabled() || $this->isLockedOut()) {
            return false;
        }

        $expectedUser = $this->config->nestedString('admin.username', 'admin');
        $expectedHash = $this->config->nestedString('admin.password_hash', '');

        if ($expectedHash === '') {
            $this->registerFailure();

            return false;
        }

        $userMatches = hash_equals($expectedUser, $username);
        $passwordMatches = password_verify($password, $expectedHash);

        if (!$userMatches || !$passwordMatches) {
            $this->registerFailure();

            return false;
        }

        $this->session->regenerate(true);
        $this->session->set(self::SESSION_AUTH, true);
        $this->session->set(self::SESSION_USER, $expectedUser);
        $this->session->set(self::SESSION_TIME, time());
        $this->session->set(self::SESSION_CSRF, self::newToken());
        $this->session->remove(self::SESSION_FAILURES);
        $this->session->remove(self::SESSION_LOCKED);

        return true;
    }

    public function logout(): void
    {
        $this->session->destroy();
    }

    /**
     * Current anti-CSRF token, created on first use.
     */
    public function csrfToken(): string
    {
        $token = $this->session->get(self::SESSION_CSRF);

        if (!is_string($token) || strlen($token) < 32) {
            $token = self::newToken();
            $this->session->set(self::SESSION_CSRF, $token);
        }

        return $token;
    }

    public function rotateCsrfToken(): string
    {
        $token = self::newToken();
        $this->session->set(self::SESSION_CSRF, $token);

        return $token;
    }

    public function validateCsrfToken(?string $token): bool
    {
        if (!is_string($token) || $token === '') {
            return false;
        }

        $expected = $this->session->get(self::SESSION_CSRF);

        return is_string($expected) && $expected !== '' && hash_equals($expected, $token);
    }

    /**
     * Seconds left in the brute-force lockout, 0 when not locked out.
     */
    public function getLockoutRemaining(): int
    {
        $lockedUntil = $this->session->get(self::SESSION_LOCKED);

        if (!is_int($lockedUntil)) {
            return 0;
        }

        return max(0, $lockedUntil - time());
    }

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return array_merge($this->blockStore->getStats(), [
            'mode' => $this->config->mode(),
            'rules_enabled' => count($this->config->stringList('enabled_rules')),
            'rate_limiter' => $this->config->string('rate_limiter', 'database'),
        ]);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getActiveBlocks(): array
    {
        return $this->blockStore->getActiveBlocks(200);
    }

    /**
     * Configuration with credentials masked, safe to render in a browser.
     *
     * @return array<array-key, mixed>
     */
    public function getSafeConfig(): array
    {
        return PayloadRedactor::redact($this->config->all());
    }

    public function unblockIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $this->blockStore->unblock($ip);

        return true;
    }

    public function blockIp(string $ip, string $reason, int $duration = 3600, string $type = 'temporary'): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        if (!in_array($type, self::BLOCK_TYPES, true)) {
            $type = 'temporary';
        }

        $this->blockStore->block($ip, $reason, $duration > 0 ? $duration : null, $type);

        return true;
    }

    private function adminEnabled(): bool
    {
        return $this->config->nestedBool('admin.enabled', false);
    }

    private function isLockedOut(): bool
    {
        $lockedUntil = $this->session->get(self::SESSION_LOCKED);

        if (!is_int($lockedUntil)) {
            return false;
        }

        if ($lockedUntil <= time()) {
            $this->session->remove(self::SESSION_LOCKED);

            return false;
        }

        return true;
    }

    private function registerFailure(): void
    {
        $failures = $this->session->get(self::SESSION_FAILURES);
        $count = is_int($failures) ? $failures + 1 : 1;

        if ($count >= self::MAX_FAILURES) {
            $this->session->set(self::SESSION_LOCKED, time() + self::LOCKOUT_SECONDS);
            $this->session->remove(self::SESSION_FAILURES);

            return;
        }

        $this->session->set(self::SESSION_FAILURES, $count);
    }

    private static function newToken(): string
    {
        return bin2hex(random_bytes(32));
    }
}
