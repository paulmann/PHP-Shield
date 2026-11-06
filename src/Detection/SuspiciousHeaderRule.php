<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class SuspiciousHeaderRule extends AbstractRule
{
    public function getName(): string
    {
        return 'suspicious_header';
    }

    public function getCategory(): string
    {
        return 'headers';
    }

    public function check(string $value, string $fieldName): array
    {
        // This rule is primarily used for User-Agent and specific headers
        $patterns = [
            '/(sqlmap|nikto|nmap|metasploit|burpsuite|acunetix|w3af)/i' => 70,
            '/(masscan|zgrab|dirbuster)/i' => 60,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Suspicious scanner User-Agent or header');
            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
