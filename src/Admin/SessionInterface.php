<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Admin;

/**
 * Minimal session abstraction so the dashboard logic is testable without
 * touching global state or PHP's session handler.
 */
interface SessionInterface
{
    public function start(): void;

    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function remove(string $key): void;

    public function regenerate(bool $deleteOld = true): void;

    public function destroy(): void;

    /**
     * @return array<string, mixed>
     */
    public function all(): array;
}
