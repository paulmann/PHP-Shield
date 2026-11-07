<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Admin\AdminAccess;
use Deynekin\PhpShield\Ip\IpResolver;
use PHPUnit\Framework\TestCase;

class AdminAccessTest extends TestCase
{
    public function testEmptyListDisablesTheGate(): void
    {
        $access = new AdminAccess([]);

        $this->assertFalse($access->isEnabled());
        $this->assertTrue($access->allows('203.0.113.5'));
        $this->assertTrue($access->allows('not-an-ip'));
        $this->assertTrue($access->allowsRequest(['REMOTE_ADDR' => '203.0.113.5']));
    }

    public function testConfiguredListAllowsOnlyItsRanges(): void
    {
        $access = $this->access(['203.0.113.0/24', '198.51.100.7', '2001:db8::/32']);

        $this->assertTrue($access->isEnabled());
        $this->assertTrue($access->allows('203.0.113.9'));
        $this->assertTrue($access->allows('198.51.100.7'));
        $this->assertTrue($access->allows('2001:db8::1'));
        $this->assertFalse($access->allows('198.51.100.8'));
        $this->assertFalse($access->allows('2001:db9::1'));
        $this->assertFalse($access->allows('not-an-ip'));
    }

    public function testAllowlistedRequestPasses(): void
    {
        $access = $this->access(['10.0.0.0/8']);

        $this->assertTrue($access->allowsRequest(['REMOTE_ADDR' => '10.1.2.3']));
        $this->assertFalse($access->allowsRequest(['REMOTE_ADDR' => '203.0.113.5']));
    }

    public function testForwardedHeaderCannotFakeAnAllowlistedAddress(): void
    {
        $access = $this->access(['10.0.0.0/8'], []);

        // No trusted proxy configured: the header is client-controlled noise.
        $this->assertFalse($access->allowsRequest([
            'REMOTE_ADDR' => '203.0.113.5',
            'HTTP_X_FORWARDED_FOR' => '10.0.0.1',
        ]));
    }

    public function testTrustedProxyHeaderIsHonoured(): void
    {
        $access = $this->access(['10.0.0.0/8'], ['127.0.0.1']);

        $this->assertTrue($access->allowsRequest([
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '10.1.2.3',
        ]));
    }

    public function testClientIpIsResolvedThroughTheProxyRules(): void
    {
        $access = $this->access(['10.0.0.0/8'], ['10.255.255.0/24']);

        $this->assertSame('203.0.113.5', $access->clientIp([
            'REMOTE_ADDR' => '10.255.255.1',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.5',
        ]));
    }

    public function testCommaSeparatedStringIsAccepted(): void
    {
        $access = new AdminAccess(['admin' => ['allowed_ips' => '10.0.0.0/8, 203.0.113.0/24 ,']]);

        $this->assertTrue($access->isEnabled());
        $this->assertTrue($access->allows('10.1.2.3'));
        $this->assertTrue($access->allows('203.0.113.9'));
        $this->assertFalse($access->allows('198.51.100.7'));
    }

    /**
     * @param list<string> $allowed
     * @param list<string> $trustedProxies
     */
    private function access(array $allowed, array $trustedProxies = []): AdminAccess
    {
        return new AdminAccess([
            'admin' => ['allowed_ips' => $allowed],
            'trusted_proxies' => $trustedProxies,
        ], new IpResolver($trustedProxies));
    }
}
