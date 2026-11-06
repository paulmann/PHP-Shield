<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Support;

use Deynekin\PhpShield\Exception\ConfigurationException;

class SecurityHeaders
{
    /**
     * Recommended defaults. Strict-Transport-Security is deliberately absent:
     * send it yourself once you know the site is HTTPS only.
     *
     * @var array<string, string>
     */
    private const DEFAULTS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-XSS-Protection' => '0', // modern browsers ignore this; CSP is preferred
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
    ];

    /**
     * Build the header list without emitting anything.
     *
     * @param array<string, string> $overrides
     * @return array<string, string>
     */
    public static function build(array $overrides = []): array
    {
        $headers = self::DEFAULTS;

        foreach ($overrides as $name => $value) {
            if (preg_match('/^[A-Za-z0-9!#$%&\'*+.^_`|~-]+$/', $name) !== 1) {
                throw new ConfigurationException("Invalid header name: '{$name}'.");
            }

            if (preg_match('/[\r\n\0]/', $value) === 1) {
                throw new ConfigurationException("Header '{$name}' contains a line break.");
            }

            $headers[$name] = $value;
        }

        return $headers;
    }

    /**
     * Send the recommended security headers.
     * Call this early in the request, before any output.
     *
     * @param array<string, string> $overrides
     */
    public static function send(array $overrides = []): void
    {
        foreach (self::build($overrides) as $name => $value) {
            header($name . ': ' . $value);
        }
    }
}
