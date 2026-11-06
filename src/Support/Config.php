<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Support;

use Deynekin\PhpShield\Exception\ConfigurationException;

/**
 * Typed, validating read access to the configuration array.
 *
 * Every accessor returns a value of the declared type or throws
 * ConfigurationException naming the offending key. This keeps the
 * middleware free of blind casts and turns configuration mistakes into
 * loud, early failures instead of silently disabled protection.
 */
final class Config
{
    public const MODES = ['monitor', 'challenge', 'block'];

    /** @param array<string, mixed> $values */
    private function __construct(private readonly array $values)
    {
    }

    /** @param array<string, mixed> $values */
    public static function fromArray(array $values): self
    {
        return new self($values);
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->values;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    public function string(string $key, string $default = ''): string
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (is_string($value)) {
            return $value;
        }

        if (is_int($value)) {
            return (string) $value;
        }

        throw new ConfigurationException("Configuration key '{$key}' must be a string.");
    }

    public function int(string $key, int $default = 0): int
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_float($value) && $value === (float) (int) $value) {
            return (int) $value;
        }

        if (is_string($value) && preg_match('/^\s*-?\d+\s*$/', $value) === 1) {
            return (int) trim($value);
        }

        throw new ConfigurationException("Configuration key '{$key}' must be an integer.");
    }

    public function nonNegativeInt(string $key, int $default = 0): int
    {
        $value = $this->int($key, $default);

        if ($value < 0) {
            throw new ConfigurationException("Configuration key '{$key}' must not be negative.");
        }

        return $value;
    }

    public function bool(string $key, bool $default = false): bool
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        if (is_string($value)) {
            $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            if ($parsed !== null) {
                return $parsed;
            }
        }

        throw new ConfigurationException("Configuration key '{$key}' must be a boolean.");
    }

    /**
     * @param list<string> $default
     * @return list<string>
     */
    public function stringList(string $key, array $default = []): array
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (!is_array($value)) {
            throw new ConfigurationException("Configuration key '{$key}' must be an array of strings.");
        }

        $list = [];

        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new ConfigurationException("Configuration key '{$key}' must contain only strings.");
            }

            $list[] = $item;
        }

        return $list;
    }

    /**
     * @param array<string, mixed> $default
     * @return array<string, mixed>
     */
    public function map(string $key, array $default = []): array
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (!is_array($value)) {
            throw new ConfigurationException("Configuration key '{$key}' must be an array.");
        }

        $map = [];

        foreach ($value as $mapKey => $item) {
            $map[(string) $mapKey] = $item;
        }

        return $map;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public function mapOfMaps(string $key): array
    {
        $value = $this->values[$key] ?? null;

        if ($value === null) {
            return [];
        }

        if (!is_array($value)) {
            throw new ConfigurationException("Configuration key '{$key}' must be an array of arrays.");
        }

        $map = [];

        foreach ($value as $mapKey => $item) {
            if (!is_array($item)) {
                throw new ConfigurationException("Configuration key '{$key}' must contain only arrays.");
            }

            $entry = [];

            foreach ($item as $entryKey => $entryValue) {
                $entry[(string) $entryKey] = $entryValue;
            }

            $map[(string) $mapKey] = $entry;
        }

        return $map;
    }

    /**
     * Read a dotted path such as 'admin.password_hash'.
     */
    public function raw(string $path, mixed $default = null): mixed
    {
        $current = $this->values;

        foreach (explode('.', $path) as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) {
                return $default;
            }

            $current = $current[$segment];
        }

        return $current;
    }

    public function nestedString(string $path, string $default = ''): string
    {
        $value = $this->raw($path);

        return is_string($value) ? $value : $default;
    }

    public function nestedInt(string $path, int $default = 0): int
    {
        $value = $this->raw($path);

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^\s*-?\d+\s*$/', $value) === 1) {
            return (int) trim($value);
        }

        return $default;
    }

    public function nestedBool(string $path, bool $default = false): bool
    {
        $value = $this->raw($path);

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        if (is_string($value)) {
            $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

            return $parsed ?? $default;
        }

        return $default;
    }

    /**
     * Operating mode, validated against the known values.
     *
     * An unrecognised mode is a hard error: silently falling through would
     * leave the middleware logging threats while never blocking anything.
     */
    public function mode(string $default = 'monitor'): string
    {
        $mode = $this->string('mode', $default);

        if (!in_array($mode, self::MODES, true)) {
            throw new ConfigurationException(
                "Configuration key 'mode' must be one of: " . implode(', ', self::MODES) . "; got '{$mode}'."
            );
        }

        return $mode;
    }

    /**
     * @return array<string, array{limit: int, window: int}>
     */
    public function rateLimits(): array
    {
        $configured = $this->mapOfMaps('rate_limits');

        if ($configured === []) {
            return ['minute' => ['limit' => 60, 'window' => 60]];
        }

        $limits = [];

        foreach ($configured as $name => $entry) {
            $limits[$name] = [
                'limit' => $this->positiveInt($name, $entry, 'limit'),
                'window' => $this->positiveInt($name, $entry, 'window'),
            ];
        }

        return $limits;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function positiveInt(string $name, array $entry, string $field): int
    {
        $value = $entry[$field] ?? null;

        if (is_int($value) && $value > 0) {
            return $value;
        }

        if (is_string($value) && preg_match('/^\s*\d+\s*$/', $value) === 1 && (int) $value > 0) {
            return (int) $value;
        }

        throw new ConfigurationException(
            "Configuration key 'rate_limits.{$name}.{$field}' must be a positive integer."
        );
    }
}
