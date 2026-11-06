<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Admin;

/**
 * Native PHP session with hardened cookie defaults.
 */
final class NativeSession implements SessionInterface
{
    /**
     * @param array{name?: string, secure?: bool|null, samesite?: string} $options
     */
    public function __construct(private readonly array $options = [])
    {
    }

    public function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // The CLI has no cookies and no headers; keep an in-memory array so
        // tools and tests can exercise the dashboard.
        if (PHP_SAPI === 'cli') {
            if (!isset($_SESSION)) {
                $_SESSION = [];
            }

            return;
        }

        if (headers_sent()) {
            return;
        }

        $name = $this->options['name'] ?? 'php_shield_admin';

        if (is_string($name) && preg_match('/^[A-Za-z0-9]{1,64}$/', $name) === 1) {
            session_name($name);
        }

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $this->isSecure(),
            'httponly' => true,
            'samesite' => $this->sameSite(),
        ]);

        session_start();
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->start();

        return $_SESSION[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->start();
        $_SESSION[$key] = $value;
    }

    public function remove(string $key): void
    {
        $this->start();
        unset($_SESSION[$key]);
    }

    public function regenerate(bool $deleteOld = true): void
    {
        $this->start();

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id($deleteOld);
        }
    }

    public function destroy(): void
    {
        $this->start();
        $_SESSION = [];

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        $this->start();
        $values = [];

        foreach ($_SESSION as $key => $value) {
            $values[(string) $key] = $value;
        }

        return $values;
    }

    private function isSecure(): bool
    {
        if (is_bool($this->options['secure'] ?? null)) {
            return (bool) $this->options['secure'];
        }

        $https = $_SERVER['HTTPS'] ?? '';

        return is_string($https) && $https !== '' && strtolower($https) !== 'off';
    }

    private function sameSite(): string
    {
        $value = $this->options['samesite'] ?? 'Strict';

        return is_string($value) && in_array($value, ['Lax', 'Strict', 'None'], true) ? $value : 'Strict';
    }
}
