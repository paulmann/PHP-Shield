<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Detection;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Support\Config;

class RuleFactory
{
    /**
     * @var array<string, class-string<AbstractRule>>
     */
    private const RULE_MAP = [
        'sql_injection' => SqlInjectionRule::class,
        'xss' => XssRule::class,
        'command_injection' => CommandInjectionRule::class,
        'path_traversal' => PathTraversalRule::class,
        'file_inclusion' => FileInclusionRule::class,
        'suspicious_header' => SuspiciousHeaderRule::class,
    ];

    /**
     * Project specific rules registered at runtime.
     *
     * @var array<string, class-string<AbstractRule>>
     */
    private static array $extraRules = [];

    /**
     * Register a custom rule without forking the library.
     *
     * The class must extend AbstractRule so it accepts the per-rule
     * configuration array.
     *
     * @param class-string<AbstractRule> $class
     */
    public static function register(string $name, string $class): void
    {
        if (preg_match('/^[a-z][a-z0-9_]{1,63}$/', $name) !== 1) {
            throw new ConfigurationException(
                "Rule name '{$name}' must start with a lowercase letter and contain only a-z, 0-9 and _."
            );
        }

        if (!class_exists($class)) {
            throw new ConfigurationException("Rule class '{$class}' does not exist.");
        }

        if (!is_subclass_of($class, AbstractRule::class)) {
            throw new ConfigurationException("Rule class '{$class}' must extend " . AbstractRule::class . '.');
        }

        self::$extraRules[$name] = $class;
    }

    /**
     * @param array<string, mixed> $config
     * @return list<RuleInterface>
     */
    public static function createFromConfig(array $config): array
    {
        $cfg = Config::fromArray($config);
        $map = self::ruleMap();

        $enabled = $cfg->has('enabled_rules') ? $cfg->stringList('enabled_rules') : array_keys($map);
        $ruleConfig = $cfg->mapOfMaps('rules');

        $rules = [];

        foreach ($enabled as $name) {
            if (!isset($map[$name])) {
                throw new ConfigurationException(
                    "Unknown rule: {$name}. Available: " . implode(', ', array_keys($map)) . '.'
                );
            }

            $class = $map[$name];
            $rules[] = new $class($ruleConfig[$name] ?? []);
        }

        return $rules;
    }

    /**
     * @return array<string, class-string<AbstractRule>>
     */
    public static function ruleMap(): array
    {
        return self::RULE_MAP + self::$extraRules;
    }

    /**
     * @return list<string>
     */
    public static function getAvailableRules(): array
    {
        return array_keys(self::ruleMap());
    }

    /**
     * Forget rules registered through register(). Intended for tests.
     */
    public static function reset(): void
    {
        self::$extraRules = [];
    }
}
