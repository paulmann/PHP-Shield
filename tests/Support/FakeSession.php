<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\Support;

use Deynekin\PhpShield\Admin\SessionInterface;

/**
 * In-memory session for tests.
 */
final class FakeSession implements SessionInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $values = [];

    public function start(): void
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $this->values[$key] = $value;
    }

    public function remove(string $key): void
    {
        unset($this->values[$key]);
    }

    public function regenerate(bool $deleteOld = true): void
    {
    }

    public function destroy(): void
    {
        $this->values = [];
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->values;
    }
}
