<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class CommandInjectionRule extends AbstractRule
{
    /**
     * Commands that make a backtick or subshell payload meaningful.
     */
    private const COMMAND_NAMES = 'cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|rm|mv|cp|chmod|chown|passwd|ssh|telnet|dd|mkfifo';

    public function getName(): string
    {
        return 'command_injection';
    }

    public function getCategory(): string
    {
        return 'injection';
    }

    public function check(string $value, string $fieldName): array
    {
        $patterns = [
            '/\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i' => 85,
            '/\|\s*(' . self::COMMAND_NAMES . ')\b/i' => 70,
            '/;\s*(' . self::COMMAND_NAMES . ')\b/i' => 75,
            '/\$\s*\(\s*(' . self::COMMAND_NAMES . ')\b/i' => 70,
            '/&&\s*(' . self::COMMAND_NAMES . ')\b/i' => 70,
            // Backticks only matter when they wrap something executable; a plain
            // `code` snippet in a comment must not be a finding.
            '/`\s*(' . self::COMMAND_NAMES . ')\b[^`]*`/i' => 60,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Potential command injection');

            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
