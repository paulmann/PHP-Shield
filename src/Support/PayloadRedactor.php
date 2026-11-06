<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Support;

class PayloadRedactor
{
    private const SENSITIVE_KEYS = [
        'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
        'authorization', 'auth', 'cookie', 'session', 'credit_card',
        'card_number', 'ssn', 'cvv', 'pin',
    ];

    private const MAX_DEPTH = 8;
    private const MAX_STRING_LENGTH = 200;

    /**
     * Replace sensitive values and truncate long strings before logging.
     *
     * @param array<array-key, mixed> $data
     * @return array<array-key, mixed>
     */
    public static function redact(array $data, int $depth = 0): array
    {
        if ($depth >= self::MAX_DEPTH) {
            return ['_truncated' => '[DEPTH_LIMIT_REACHED]'];
        }

        $redacted = [];

        foreach ($data as $key => $value) {
            $plainKey = is_string($key) ? $key : (string) $key;

            if (self::isSensitive($plainKey)) {
                $redacted[$key] = '[REDACTED]';

                continue;
            }

            if (is_array($value)) {
                $redacted[$key] = self::redact($value, $depth + 1);

                continue;
            }

            if (is_object($value)) {
                $redacted[$key] = '[OBJECT ' . $value::class . ']';

                continue;
            }

            $redacted[$key] = is_string($value) ? self::truncate($value) : $value;
        }

        return $redacted;
    }

    private static function isSensitive(string $key): bool
    {
        $lowerKey = strtolower($key);

        foreach (self::SENSITIVE_KEYS as $sensitive) {
            if (str_contains($lowerKey, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    private static function truncate(string $value): string
    {
        $length = mb_check_encoding($value, 'UTF-8') ? mb_strlen($value, 'UTF-8') : strlen($value);

        if ($length <= self::MAX_STRING_LENGTH) {
            return $value;
        }

        $short = mb_check_encoding($value, 'UTF-8')
            ? mb_substr($value, 0, self::MAX_STRING_LENGTH, 'UTF-8')
            : substr($value, 0, self::MAX_STRING_LENGTH);

        return $short . '...[truncated]';
    }
}
