<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Middleware\SecurityMiddleware;
use Deynekin\PhpShield\Tests\Support\InMemoryBlockStore;
use PHPUnit\Framework\TestCase;

class SecurityMiddlewareTest extends TestCase
{
    private InMemoryBlockStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryBlockStore();
    }

    public function testTemporaryBlockCarriesSeverityAndExpiry(): void
    {
        $this->middleware()->blockIp('203.0.113.5', 'Scanner', SecurityMiddleware::SEVERITY_HIGH);

        $block = $this->store->blocks['203.0.113.5'];

        $this->assertSame('temporary', $block['type']);
        $this->assertSame('high', $block['severity']);
        $this->assertSame(14400, $block['expiresAt'] - time());
        $this->assertTrue($this->middleware()->isIpBlocked('203.0.113.5'));
    }

    public function testExplicitTtlWinsOverSeverity(): void
    {
        $this->middleware()->blockIp('203.0.113.5', 'Short', SecurityMiddleware::SEVERITY_CRITICAL, 60);

        $this->assertSame(60, $this->store->blocks['203.0.113.5']['expiresAt'] - time());
    }

    public function testPermanentBlockHasNoExpiry(): void
    {
        $this->middleware()->blockPermanently('203.0.113.5', 'Manual decision');

        $this->assertNull($this->store->blocks['203.0.113.5']['expiresAt']);
        $this->assertTrue($this->store->isPermanentlyBlocked('203.0.113.5'));
    }

    public function testTrustedAddressIsNeverBlocked(): void
    {
        $middleware = $this->middleware(['trusted_ips' => ['10.0.0.0/8']]);

        $middleware->blockIp('10.1.2.3', 'should be ignored');

        $this->assertArrayNotHasKey('10.1.2.3', $this->store->blocks);
        $this->assertFalse($middleware->isIpBlocked('10.1.2.3'));
        $this->assertTrue($middleware->isTrustedIp('10.1.2.3'));
    }

    public function testUnblockValidatesTheAddress(): void
    {
        $middleware = $this->middleware();
        $middleware->blockIp('203.0.113.5', 'test');

        $this->assertFalse($middleware->unblockIp('not-an-ip'));
        $this->assertTrue($middleware->unblockIp('203.0.113.5'));
        $this->assertFalse($middleware->isIpBlocked('203.0.113.5'));
    }

    public function testIncidentSeverityIsNormalised(): void
    {
        $this->middleware()->recordIncident('203.0.113.5', 'test', 'desc', 'bogus');

        $this->assertSame('medium', $this->store->incidents[0]['severity']);
    }

    public function testIncidentWindowCounters(): void
    {
        $middleware = $this->middleware();
        $middleware->recordIncident('203.0.113.5', 'a', 'first');
        $middleware->recordIncident('203.0.113.5', 'b', 'second');

        $this->assertSame(2, $middleware->recentIncidentCount('203.0.113.5'));
        $this->assertCount(2, $middleware->recentIncidents());
    }

    public function testFailedAttemptCounters(): void
    {
        $middleware = $this->middleware();

        $this->assertSame(1, $middleware->recordFailedAttempt('203.0.113.5'));
        $this->assertSame(2, $middleware->recordFailedAttempt('203.0.113.5'));
        $this->assertSame(2, $middleware->failedAttempts('203.0.113.5'));

        $middleware->clearFailedAttempts('203.0.113.5');
        $this->assertSame(0, $middleware->failedAttempts('203.0.113.5'));
    }

    public function testCleanupAndStatsDelegateToTheStore(): void
    {
        $middleware = $this->middleware();
        $middleware->recordIncident('203.0.113.5', 'test', 'desc');

        $cleanup = $middleware->cleanup(30);

        $this->assertArrayHasKey('incidents', $cleanup);
        $this->assertSame([], $this->store->incidents);
        $this->assertArrayHasKey('incidents_total', $middleware->stats());
    }

    public function testSeverityNormalisationAndRanking(): void
    {
        $middleware = $this->middleware();

        $this->assertSame('critical', $middleware->normalizeSeverity('CRITICAL'));
        $this->assertSame('medium', $middleware->normalizeSeverity('nonsense'));
        $this->assertGreaterThan($middleware->severityRank('medium'), $middleware->severityRank('high'));
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function middleware(array $overrides = []): SecurityMiddleware
    {
        return new SecurityMiddleware($this->store, array_merge([
            'trusted_ips' => [],
            'block_duration' => 3600,
            'max_failed_attempts' => 25,
        ], $overrides));
    }
}
