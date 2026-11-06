<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Ip\CidrMatcher;
use PHPUnit\Framework\TestCase;

class CidrMatcherTest extends TestCase
{
    public function testIpv4ExactMatch(): void
    {
        $this->assertTrue(CidrMatcher::ipInRange('192.168.1.1', '192.168.1.1'));
        $this->assertFalse(CidrMatcher::ipInRange('192.168.1.2', '192.168.1.1'));
    }

    public function testIpv4Cidr(): void
    {
        $this->assertTrue(CidrMatcher::ipInRange('192.168.1.100', '192.168.1.0/24'));
        $this->assertFalse(CidrMatcher::ipInRange('192.168.2.1', '192.168.1.0/24'));
        $this->assertTrue(CidrMatcher::ipInRange('10.0.0.1', '10.0.0.0/8'));
        $this->assertTrue(CidrMatcher::ipInRange('172.16.5.5', '172.16.0.0/12'));
    }

    public function testIpv6(): void
    {
        $this->assertTrue(CidrMatcher::ipInRange('::1', '::1'));
        $this->assertTrue(CidrMatcher::ipInRange('::1', '::1/128'));
        $this->assertTrue(CidrMatcher::ipInRange('2001:db8::1', '2001:db8::/32'));
        $this->assertFalse(CidrMatcher::ipInRange('2001:db9::1', '2001:db8::/32'));
    }

    public function testIsTrusted(): void
    {
        $ranges = ['127.0.0.1', '10.0.0.0/8', '::1'];
        $this->assertTrue(CidrMatcher::isTrusted('127.0.0.1', $ranges));
        $this->assertTrue(CidrMatcher::isTrusted('10.1.2.3', $ranges));
        $this->assertFalse(CidrMatcher::isTrusted('8.8.8.8', $ranges));
    }

    public function testInvalidRanges(): void
    {
        $this->assertFalse(CidrMatcher::ipInRange('not-an-ip', '10.0.0.0/8'));
        $this->assertFalse(CidrMatcher::ipInRange('10.0.0.1', 'invalid'));
    }
}
