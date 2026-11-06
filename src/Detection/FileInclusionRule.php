<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class FileInclusionRule extends AbstractRule
{
    public function getName(): string
    {
        return 'file_inclusion';
    }

    public function getCategory(): string
    {
        return 'inclusion';
    }

    public function check(string $value, string $fieldName): array
    {
        $patterns = [
            '/\b(include|require)(_once)?\s*\(\s*[\'"]?(https?|ftp|php):/i' => 80,
            '/\b(include|require)(_once)?\s*\(\s*[\'"]?\.\.\//' => 70,
            '/file_get_contents\s*\(\s*[\'"]?(https?|ftp):/i' => 60,
            '/php:\/\/filter/i' => 85,
            '/php:\/\/input/i' => 75,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Potential file inclusion');
            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
