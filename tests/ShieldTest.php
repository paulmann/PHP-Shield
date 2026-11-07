<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Ip\IpResolver;
use Deynekin\PhpShield\Middleware\SecurityMiddleware;
use Deynekin\PhpShield\Middleware\Shield;
use Deynekin\PhpShield\Tests\Support\FakeRateLimiter;
use Deynekin\PhpShield\Tests\Support\InMemoryBlockStore;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationCache;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationQueue;
use Deynekin\PhpShield\ThreatIntel\ReputationChecker;
use Deynekin\PhpShield\ThreatIntel\ReputationWorker;
use PHPUnit\Framework\TestCase;

class ShieldTest extends TestCase
{
    private InMemoryBlockStore $store;

    private FakeRateLimiter $limiter;

    protected function setUp(): void
    {
        $this->store = new InMemoryBlockStore();
        $this->limiter = new FakeRateLimiter();
    }

    public function testAllowsCleanRequest(): void
    {
        $decision = $this->shield()->inspect(
            ['name' => 'Alice', 'comment' => 'Nice article'],
            ['REMOTE_ADDR' => '203.0.113.5']
        );

        $this->assertFalse($decision['blocked']);
        $this->assertSame(200, $decision['status']);
        $this->assertSame([], $this->store->incidents);
    }

    public function testRejectsPermanentlyBlockedAddress(): void
    {
        $this->store->block('203.0.113.5', 'Known attacker', null, 'permanent', 'critical');

        $decision = $this->shield()->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame('ip_blocked', $decision['reason']);
        $this->assertSame(403, $decision['status']);
    }

    public function testRejectsTemporarilyBlockedAddress(): void
    {
        $this->store->block('203.0.113.5', 'Rate limit', 3600);

        $this->assertTrue($this->shield()->inspect([], ['REMOTE_ADDR' => '203.0.113.5'])['blocked']);
    }

    public function testTrustedAddressBypassesEverything(): void
    {
        $shield = $this->shield(['trusted_ips' => ['10.0.0.0/8']]);

        $decision = $shield->inspect(['q' => '<script>alert(1)</script>'], ['REMOTE_ADDR' => '10.1.2.3']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame([], $this->store->incidents);
    }

    public function testMonitorModeLogsButAllows(): void
    {
        $decision = $this->shield(['mode' => 'monitor'])->inspect(
            ['q' => '<script>alert(1)</script>'],
            ['REMOTE_ADDR' => '203.0.113.5']
        );

        $this->assertFalse($decision['blocked']);
        $this->assertSame('threat_detected', $this->store->incidents[0]['type']);
        $this->assertSame('critical', $this->store->incidents[0]['severity']);
    }

    public function testBlockModeBlocksHighScoreThreat(): void
    {
        $decision = $this->shield()->inspect(['q' => '<script>alert(1)</script>'], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame('threat_detected', $decision['reason']);
        $this->assertContains('xss', $decision['findings']);
        $this->assertTrue($this->store->isBlocked('203.0.113.5'));
        $this->assertSame('critical', $this->store->blocks['203.0.113.5']['severity']);
    }

    public function testChallengeModeRefusesWithoutBlocking(): void
    {
        $decision = $this->shield(['mode' => 'challenge'])->inspect(
            ['q' => "1' UNION SELECT password FROM users --"],
            ['REMOTE_ADDR' => '203.0.113.5']
        );

        $this->assertTrue($decision['blocked']);
        $this->assertSame('challenge_required', $decision['reason']);
        $this->assertFalse($this->store->isBlocked('203.0.113.5'));
    }

    public function testRateLimitBreachBlocksWith429(): void
    {
        $this->limiter->allow = false;

        $decision = $this->shield()->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame(429, $decision['status']);
        $this->assertSame('rate_limit', $this->store->incidents[0]['type']);
    }

    public function testRateLimitBreachAllowsInMonitorMode(): void
    {
        $this->limiter->allow = false;

        $decision = $this->shield(['mode' => 'monitor'])->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame('rate_limit', $this->store->incidents[0]['type']);
    }

    public function testScansRequestUri(): void
    {
        $decision = $this->shield()->inspect(
            [],
            ['REMOTE_ADDR' => '203.0.113.5', 'REQUEST_URI' => '/search?q=%3Cscript%3Ealert(1)%3C/script%3E']
        );

        $this->assertTrue($decision['blocked']);
        $this->assertSame('__request_uri', $this->firstThreatField());
    }

    public function testDetectsPercentEncodedPayload(): void
    {
        $decision = $this->shield(['mode' => 'monitor'])->inspect(
            ['q' => '%3Cscript%3Ealert(1)%3C%2Fscript%3E'],
            ['REMOTE_ADDR' => '203.0.113.5']
        );

        $this->assertFalse($decision['blocked']);
        $this->assertCount(1, $this->store->incidents);
    }

    public function testDeduplicatesRepeatedMatchesForSameField(): void
    {
        $threats = $this->shield()->scanData(['q' => '<script>alert(1)</script>%3Cscript%3E']);

        $this->assertCount(1, $threats);
    }

    public function testScansNestedArraysAndNamesThePath(): void
    {
        $threats = $this->shield()->scanData(['profile' => ['bio' => '<script>alert(1)</script>']]);

        $this->assertCount(1, $threats);
        $this->assertSame('profile.bio', $threats[0]['field']);
    }

    public function testSuspiciousUserAgentIsBlocked(): void
    {
        $decision = $this->shield()->inspect(
            [],
            ['REMOTE_ADDR' => '203.0.113.5', 'HTTP_USER_AGENT' => 'sqlmap/1.7.2#stable']
        );

        $this->assertTrue($decision['blocked']);
        $this->assertSame('suspicious_ua', $this->store->incidents[0]['type']);
    }

    public function testUnknownModeIsRejectedLoudly(): void
    {
        $shield = $this->shield(['mode' => 'blocks']);

        $this->expectException(ConfigurationException::class);
        $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);
    }

    public function testFailedAttemptsEscalateToBlock(): void
    {
        $this->store->attempts['203.0.113.5'] = 25;

        $decision = $this->shield()->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame('too_many_failures', $decision['reason']);
        $this->assertTrue($this->store->isBlocked('203.0.113.5'));
        $this->assertSame(0, $this->store->getFailedAttempts('203.0.113.5'));
    }

    public function testReputationAboveBlockScoreBlocks(): void
    {
        $shield = $this->shield([], $this->reputationChecker($this->reputationResponse(95)));

        $decision = $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame('ip_reputation', $decision['reason']);
        $this->assertSame('critical', $this->store->blocks['203.0.113.5']['severity']);
        $this->assertSame('ip_reputation', $this->store->incidents[0]['type']);
    }

    public function testReputationInMonitorModeOnlyJournals(): void
    {
        $shield = $this->shield(['mode' => 'monitor'], $this->reputationChecker($this->reputationResponse(95)));

        $decision = $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame('ip_reputation', $this->store->incidents[0]['type']);
    }

    public function testReputationBetweenFlagAndBlockOnlyJournals(): void
    {
        $shield = $this->shield([], $this->reputationChecker($this->reputationResponse(40)));

        $decision = $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame('ip_reputation_flag', $this->store->incidents[0]['type']);
    }

    public function testLowReputationScoreIsIgnored(): void
    {
        $shield = $this->shield([], $this->reputationChecker($this->reputationResponse(5)));

        $decision = $shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame([], $this->store->incidents);
    }

    public function testWhitelistedAddressWithHighScoreIsAllowed(): void
    {
        $body = $this->reputationResponse(100, whitelisted: true);
        $shield = $this->shield([], $this->reputationChecker($body));

        $this->assertFalse($shield->inspect([], ['REMOTE_ADDR' => '203.0.113.5'])['blocked']);
    }

    public function testReputationOutageFailsOpen(): void
    {
        $transport = new \Deynekin\PhpShield\Tests\Support\FakeTransport();
        $transport->respondWithException(
            \Deynekin\PhpShield\Exception\ThreatIntelException::unavailable('abuseipdb.com', 'timeout')
        );

        $checker = new ReputationChecker(
            [new AbuseIpDbProvider($transport, 'key')],
            new ArrayReputationCache()
        );

        $this->assertFalse($this->shield([], $checker)->inspect([], ['REMOTE_ADDR' => '203.0.113.5'])['blocked']);
        $this->assertSame([], $this->store->incidents);
    }

    public function testSeverityDrivesBlockDuration(): void
    {
        $middleware = $this->shield()->middleware();

        $this->assertSame(3600, $middleware->durationFor(SecurityMiddleware::SEVERITY_MEDIUM));
        $this->assertSame(43200, $middleware->durationFor(SecurityMiddleware::SEVERITY_CRITICAL));
        $this->assertSame(1800, $middleware->durationFor(SecurityMiddleware::SEVERITY_LOW));
    }

    public function testBooleanFacade(): void
    {
        $shield = $this->shield();

        $this->assertTrue($shield->isRequestAllowed(['q' => 'hello'], ['REMOTE_ADDR' => '203.0.113.5']));
        $this->assertFalse($shield->isRequestAllowed(['q' => '<script>alert(1)</script>'], ['REMOTE_ADDR' => '203.0.113.6']));
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function shield(array $overrides = [], ?ReputationChecker $reputation = null): Shield
    {
        $config = $this->config($overrides);

        return new Shield(
            new SecurityMiddleware($this->store, $config),
            $this->limiter,
            new IpResolver($config['trusted_proxies']),
            $config,
            $reputation
        );
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides = []): array
    {
        return array_merge([
            'enabled' => true,
            'mode' => 'block',
            'enabled_rules' => ['sql_injection', 'xss', 'suspicious_header'],
            'trusted_ips' => [],
            'trusted_proxies' => [],
            'rate_limits' => ['minute' => ['limit' => 60, 'window' => 60]],
            'block_threshold' => 50,
            'challenge_threshold' => 30,
            'suspicious_threshold' => 20,
            'block_duration' => 3600,
            'rate_limit_block_duration' => 300,
            'max_failed_attempts' => 25,
            'scan_request_uri' => true,
            'ip_reputation' => ['block_score' => 75, 'flag_score' => 25],
        ], $overrides);
    }

    public function testAsyncReputationDoesNotTouchTheNetwork(): void
    {
        $transport = new \Deynekin\PhpShield\Tests\Support\FakeTransport();
        $queue = new ArrayReputationQueue();
        $checker = new ReputationChecker(
            [new AbuseIpDbProvider($transport, 'test-key')],
            new ArrayReputationCache(),
            86400,
            5,
            120,
            $queue,
            true
        );

        $decision = $this->shield([], $checker)->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertFalse($decision['blocked']);
        $this->assertSame([], $transport->requests);
        $this->assertSame(1, $queue->size());
        $this->assertSame([], $this->store->incidents);
    }

    public function testAsyncReputationBlocksOnceTheWorkerFilledTheCache(): void
    {
        $transport = (new \Deynekin\PhpShield\Tests\Support\FakeTransport())
            ->respond(200, $this->reputationResponse(95));
        $queue = new ArrayReputationQueue();
        $checker = new ReputationChecker(
            [new AbuseIpDbProvider($transport, 'test-key')],
            new ArrayReputationCache(),
            86400,
            5,
            120,
            $queue,
            true
        );

        $queue->push('203.0.113.5');
        (new ReputationWorker($queue, $checker))->drain();

        $decision = $this->shield([], $checker)->inspect([], ['REMOTE_ADDR' => '203.0.113.5']);

        $this->assertTrue($decision['blocked']);
        $this->assertSame('ip_reputation', $decision['reason']);
        $this->assertCount(1, $transport->requests, 'only the worker talks to the API');
    }

    private function reputationChecker(string $body): ReputationChecker
    {
        $transport = new \Deynekin\PhpShield\Tests\Support\FakeTransport();
        $transport->respond(200, $body);

        return new ReputationChecker([new AbuseIpDbProvider($transport, 'test-key')], new ArrayReputationCache());
    }

    private function reputationResponse(int $score, bool $whitelisted = false): string
    {
        return (string) json_encode([
            'data' => [
                'ipAddress' => '203.0.113.5',
                'isPublic' => true,
                'isWhitelisted' => $whitelisted,
                'abuseConfidenceScore' => $score,
                'countryCode' => 'RU',
                'usageType' => 'Data Center/Web Hosting/Transit',
                'isp' => 'Example ISP',
                'totalReports' => 12,
                'numDistinctUsers' => 4,
                'lastReportedAt' => '2026-11-06T18:39:06+00:00',
            ],
        ]);
    }

    private function firstThreatField(): string
    {
        $context = $this->store->incidents[0]['context'] ?? [];
        $threats = is_array($context) && isset($context['threats']) && is_array($context['threats']) ? $context['threats'] : [];
        $first = $threats[0] ?? [];

        return is_array($first) && isset($first['field']) && is_string($first['field']) ? $first['field'] : '';
    }
}
