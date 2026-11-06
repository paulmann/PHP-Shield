<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class XssRule extends AbstractRule
{
    public function getName(): string
    {
        return 'xss';
    }

    public function getCategory(): string
    {
        return 'xss';
    }

    public function check(string $value, string $fieldName): array
    {
        $patterns = [
            '/<script\b[^>]*>/i' => 90,
            '/javascript\s*:/i' => 70,
            '/on(load|error|click|mouseover|focus)\s*=/i' => 60,
            '/<iframe\b[^>]*>/i' => 50,
            '/<object\b[^>]*>/i' => 50,
            '/<embed\b[^>]*>/i' => 50,
            '/document\.(cookie|write|location)/i' => 40,
            '/eval\s*\(/i' => 65,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Potential XSS pattern');
            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
