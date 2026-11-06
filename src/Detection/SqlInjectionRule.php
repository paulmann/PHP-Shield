<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class SqlInjectionRule extends AbstractRule
{
    public function getName(): string
    {
        return 'sql_injection';
    }

    public function getCategory(): string
    {
        return 'injection';
    }

    public function check(string $value, string $fieldName): array
    {
        // More precise patterns to reduce false positives
        $patterns = [
            '/\bUNION\s+(ALL\s+)?SELECT\b/i' => 50,
            '/\bDROP\s+TABLE\b/i' => 80,
            '/\bSLEEP\s*\(\s*\d+/i' => 60,
            '/\bBENCHMARK\s*\(/i' => 60,
            '/\bOR\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i' => 30,
            '/\bAND\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i' => 25,
            '/;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\b/i' => 70,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Potential SQL injection pattern');
            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
