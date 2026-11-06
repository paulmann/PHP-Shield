<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Detection\RuleFactory;
use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Tests\Support\CustomRule;
use PHPUnit\Framework\TestCase;

class RuleFactoryTest extends TestCase
{
    protected function tearDown(): void
    {
        RuleFactory::reset();
    }

    public function testCreatesEnabledRules(): void
    {
        $config = [
            'enabled_rules' => ['xss', 'sql_injection'],
            'rules' => [
                'xss' => ['enabled' => true],
            ],
        ];

        $rules = RuleFactory::createFromConfig($config);
        $this->assertCount(2, $rules);
        $this->assertSame('xss', $rules[0]->getName());
        $this->assertSame('sql_injection', $rules[1]->getName());
    }

    public function testThrowsOnUnknownRule(): void
    {
        $this->expectException(ConfigurationException::class);
        RuleFactory::createFromConfig(['enabled_rules' => ['unknown_rule']]);
    }

    public function testGetAvailableRules(): void
    {
        $available = RuleFactory::getAvailableRules();
        $this->assertContains('xss', $available);
        $this->assertContains('sql_injection', $available);
        $this->assertContains('suspicious_header', $available);
        $this->assertCount(6, $available);
    }

    public function testRegistersCustomRule(): void
    {
        RuleFactory::register('custom_test', CustomRule::class);

        $rules = RuleFactory::createFromConfig([
            'enabled_rules' => ['custom_test'],
            'rules' => ['custom_test' => ['enabled' => true]],
        ]);

        $this->assertCount(1, $rules);
        $this->assertInstanceOf(CustomRule::class, $rules[0]);
        $this->assertContains('custom_test', RuleFactory::getAvailableRules());
        $this->assertTrue($rules[0]->check('evil payload', 'field')['matched']);
    }

    public function testRejectsInvalidRuleName(): void
    {
        $this->expectException(ConfigurationException::class);
        RuleFactory::register('Custom Rule!', CustomRule::class);
    }

    public function testRejectsRuleThatDoesNotExtendAbstractRule(): void
    {
        $this->expectException(ConfigurationException::class);
        RuleFactory::register('custom_test', \stdClass::class);
    }

    public function testRejectsUnknownClass(): void
    {
        $this->expectException(ConfigurationException::class);
        /** @phpstan-ignore-next-line intentionally invalid class */
        RuleFactory::register('custom_test', 'App\\Missing\\Rule');
    }
}
