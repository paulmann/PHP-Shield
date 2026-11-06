<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Support\SecurityHeaders;
use PHPUnit\Framework\TestCase;

class SecurityHeadersTest extends TestCase
{
    public function testBuildContainsRecommendedHeaders(): void
    {
        $headers = SecurityHeaders::build();

        $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
        $this->assertArrayHasKey('Content-Security-Policy', $headers);
        $this->assertArrayHasKey('Referrer-Policy', $headers);
        // HSTS stays opt-in: it must not be sent over plain HTTP.
        $this->assertArrayNotHasKey('Strict-Transport-Security', $headers);
    }

    public function testOverridesReplaceAndAdd(): void
    {
        $headers = SecurityHeaders::build([
            'X-Frame-Options' => 'DENY',
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        ]);

        $this->assertSame('DENY', $headers['X-Frame-Options']);
        $this->assertArrayHasKey('Strict-Transport-Security', $headers);
    }

    public function testRejectsHeaderNameInjection(): void
    {
        $this->expectException(ConfigurationException::class);
        SecurityHeaders::build(['X-Test: evil' => 'value']);
    }

    public function testRejectsHeaderValueInjection(): void
    {
        $this->expectException(ConfigurationException::class);
        SecurityHeaders::build(['X-Test' => "value\r\nX-Injected: yes"]);
    }
}
