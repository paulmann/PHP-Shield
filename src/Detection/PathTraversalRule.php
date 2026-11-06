<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

class PathTraversalRule extends AbstractRule
{
    public function getName(): string
    {
        return 'path_traversal';
    }

    public function getCategory(): string
    {
        return 'path';
    }

    public function check(string $value, string $fieldName): array
    {
        $patterns = [
            '/(\.\.\/){2,}/' => 60,
            '/(\.\.\\\\){2,}/' => 60,
            '/\/etc\/passwd/i' => 90,
            '/\/etc\/shadow/i' => 95,
            '/\/\.ssh\//i' => 80,
            '/\/proc\/self\//i' => 70,
        ];

        foreach ($patterns as $pattern => $score) {
            $result = $this->match($pattern, $value, $fieldName, $score, 'Potential path traversal');
            if ($result['matched']) {
                return $result;
            }
        }

        return ['matched' => false];
    }
}
