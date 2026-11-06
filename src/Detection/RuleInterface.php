<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

interface RuleInterface
{
    public function getName(): string;

    public function getCategory(): string;

    /**
     * @return array{matched: bool, pattern?: string, score?: int, description?: string}
     */
    public function check(string $value, string $fieldName): array;

    public function isEnabled(): bool;
}
