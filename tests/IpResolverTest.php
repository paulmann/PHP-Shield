<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Ip\IpResolver;
use PHPUnit\Framework\TestCase;

class IpResolverTest extends TestCase
{
    public function testDirectConnectionWithoutProxy(): void
    {
        $resolver = new IpResolver([]);
        $server = ['REMOTE_ADDR' => '203.0.113.5'];
        $this->assertSame('203.0.113.5', $resolver->resolve($server));
    }

    public function testIgnoresForwardedHeadersWhenNotFromTrustedProxy(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server = [
            'REMOTE_ADDR' => '203.0.113.5',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.10',
        ];
        $this->assertSame('203.0.113.5', $resolver->resolve($server));
    }

    public function testHonorsForwardedHeaderFromTrustedProxy(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server = [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.10, 10.0.0.5',
        ];
        $this->assertSame('198.51.100.10', $resolver->resolve($server));
    }

    public function testXRealIpFromTrustedProxy(): void
    {
        $resolver = new IpResolver(['127.0.0.1']);
        $server = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_REAL_IP' => '203.0.113.42',
        ];
        $this->assertSame('203.0.113.42', $resolver->resolve($server));
    }

    public function testStripsIpv6ZoneId(): void
    {
        $resolver = new IpResolver([]);
        $server = ['REMOTE_ADDR' => 'fe80::1%eth0'];
        $this->assertSame('fe80::1', $resolver->resolve($server));
    }

    public function testIgnoresSpoofedLeftmostForwardedEntry(): void
    {
        // This is the classic spoof: the client prepends a "trusted" address and
        // the proxy appends the real one. Reading the left-most entry would let
        // the attacker pick their own IP (and bypass trusted_ips entirely).
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server = [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 203.0.113.9',
        ];

        $this->assertSame('203.0.113.9', $resolver->resolve($server));
    }

    public function testSkipsSeveralTrustedProxiesInChain(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8', '172.16.0.0/12']);
        $server = [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 172.16.1.1, 10.0.0.5',
        ];

        $this->assertSame('198.51.100.7', $resolver->resolve($server));
    }

    public function testFallsBackToLeftmostWhenEveryHopIsTrusted(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server = [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '10.1.1.1, 10.0.0.5',
        ];

        $this->assertSame('10.1.1.1', $resolver->resolve($server));
    }

    public function testInvalidForwardedEntriesAreIgnored(): void
    {
        $resolver = new IpResolver(['10.0.0.0/8']);
        $server = [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => 'unknown, , 203.0.113.11',
        ];

        $this->assertSame('203.0.113.11', $resolver->resolve($server));
    }

    public function testNonIpRemoteAddressBecomesZeroAddress(): void
    {
        $resolver = new IpResolver([]);

        $this->assertSame('0.0.0.0', $resolver->resolve(['REMOTE_ADDR' => 'not-an-ip']));
        $this->assertSame('0.0.0.0', $resolver->resolve([]));
    }

    public function testStripsPortFromForwardedValue(): void
    {
        $resolver = new IpResolver(['127.0.0.1']);
        $server = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_REAL_IP' => '203.0.113.44:5678',
        ];

        $this->assertSame('203.0.113.44', $resolver->resolve($server));
    }
}
