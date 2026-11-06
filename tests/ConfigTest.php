<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Support\Config;
use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{
    public function testReturnsDefaultsForMissingKeys(): void
    {
        $config = Config::fromArray([]);

        $this->assertSame('fallback', $config->string('missing', 'fallback'));
        $this->assertSame(7, $config->int('missing', 7));
        $this->assertTrue($config->bool('missing', true));
        $this->assertSame(['10.0.0.0/8'], $config->stringList('missing', ['10.0.0.0/8']));
        $this->assertFalse($config->has('missing'));
    }

    public function testCoercesNumericStrings(): void
    {
        $config = Config::fromArray(['threshold' => '50', 'enabled' => 'false', 'port' => 6379]);

        $this->assertSame(50, $config->int('threshold'));
        $this->assertFalse($config->bool('enabled'));
        $this->assertSame('6379', $config->string('port'));
    }

    public function testRejectsWrongTypes(): void
    {
        $config = Config::fromArray(['threshold' => 'fifty', 'trusted' => '10.0.0.0/8']);

        $this->expectException(ConfigurationException::class);
        $config->int('threshold');
    }

    public function testStringListRejectsNonStrings(): void
    {
        $config = Config::fromArray(['trusted_proxies' => ['10.0.0.1', 42]]);

        $this->expectException(ConfigurationException::class);
        $config->stringList('trusted_proxies');
    }

    public function testModeDefaultsToMonitorAndRejectsUnknownValues(): void
    {
        $this->assertSame('monitor', Config::fromArray([])->mode());

        $this->expectException(ConfigurationException::class);
        Config::fromArray(['mode' => 'blocks'])->mode();
    }

    public function testModeAcceptsKnownValues(): void
    {
        foreach (['monitor', 'challenge', 'block'] as $mode) {
            $this->assertSame($mode, Config::fromArray(['mode' => $mode])->mode());
        }
    }

    public function testRateLimitsValidation(): void
    {
        $limits = Config::fromArray([
            'rate_limits' => ['minute' => ['limit' => 60, 'window' => 60]],
        ])->rateLimits();

        $this->assertSame(['minute' => ['limit' => 60, 'window' => 60]], $limits);

        $this->expectException(ConfigurationException::class);
        Config::fromArray(['rate_limits' => ['minute' => ['limit' => 0, 'window' => 60]]])->rateLimits();
    }

    public function testDottedPathAccess(): void
    {
        $config = Config::fromArray([
            'admin' => ['username' => 'root', 'enabled' => true],
        ]);

        $this->assertSame('root', $config->nestedString('admin.username'));
        $this->assertTrue($config->nestedBool('admin.enabled'));
        $this->assertSame('fallback', $config->nestedString('admin.missing', 'fallback'));
        $this->assertNull($config->raw('admin.nothing.here'));
    }

    public function testNonNegativeIntRejectsNegativeValues(): void
    {
        $this->expectException(ConfigurationException::class);
        Config::fromArray(['block_duration' => -1])->nonNegativeInt('block_duration', 3600);
    }
}
