<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\Support;

use Deynekin\PhpShield\Detection\AbstractRule;

/**
 * Custom rule used to prove RuleFactory::register() works.
 */
final class CustomRule extends AbstractRule
{
    public function getName(): string
    {
        return 'custom_test';
    }

    public function getCategory(): string
    {
        return 'custom';
    }

    public function check(string $value, string $fieldName): array
    {
        return $this->match('/evil/i', $value, $fieldName, 45, 'Custom evil pattern');
    }
}
