<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

abstract class AbstractRule implements RuleInterface
{
    protected bool $enabled = true;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(protected readonly array $config = [])
    {
        $this->enabled = (bool) ($config['enabled'] ?? true);
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * @return array{matched: bool, pattern?: string, score?: int, description?: string, field?: string, snippet?: string}
     */
    protected function match(string $pattern, string $value, string $fieldName, int $score = 10, string $description = ''): array
    {
        if (!$this->isEnabled()) {
            return ['matched' => false];
        }

        if (@preg_match($pattern, $value) === 1) {
            return [
                'matched' => true,
                'pattern' => $this->getName(),
                'score' => $score,
                'description' => $description !== '' ? $description : "Matched pattern in field '{$fieldName}'",
                'field' => $fieldName,
                'snippet' => mb_substr($value, 0, 80),
            ];
        }

        return ['matched' => false];
    }
}
