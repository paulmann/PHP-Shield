<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\Tests\Support\FakeTransport;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationCache;
use Deynekin\PhpShield\ThreatIntel\ReputationChecker;
use PHPUnit\Framework\TestCase;

class ReputationCheckerTest extends TestCase
{
    public function testDisabledWithoutProviders(): void
    {
        $checker = new ReputationChecker([], new ArrayReputationCache());

        $this->assertFalse($checker->isEnabled());
        $this->assertNull($checker->lookup('203.0.113.5'));
    }

    public function testCachesTheAnswer(): void
    {
        $transport = (new FakeTransport())->respond(200, $this->payload(90));
        $checker = $this->checker([AbuseIpDbProvider::com($transport, 'key')]);

        $first = $checker->lookup('203.0.113.5');
        $second = $checker->lookup('203.0.113.5');

        $this->assertSame(90, $first?->abuseConfidenceScore);
        $this->assertSame(90, $second?->abuseConfidenceScore);
        $this->assertCount(1, $transport->requests);
    }

    public function testFallsBackToTheSecondProvider(): void
    {
        $broken = (new FakeTransport())->respondWithException(
            ThreatIntelException::unavailable('abuseipdb.com', 'connection timed out')
        );
        $ru = (new FakeTransport())->respond(200, $this->payload(70));

        $checker = $this->checker([
            AbuseIpDbProvider::com($broken, 'key'),
            AbuseIpDbProvider::ru($ru, 'ru-key'),
        ]);

        $reputation = $checker->lookup('203.0.113.5');

        $this->assertNotNull($reputation);
        $this->assertSame('abuseipdb.ru', $reputation->provider);
        $this->assertSame(70, $reputation->abuseConfidenceScore);
    }

    public function testBreakerOpensAfterRepeatedFailures(): void
    {
        $transport = (new FakeTransport())
            ->respondWithException(ThreatIntelException::unavailable('abuseipdb.com', 'down'))
            ->respondWithException(ThreatIntelException::unavailable('abuseipdb.com', 'down'))
            ->respondWithException(ThreatIntelException::unavailable('abuseipdb.com', 'down'));

        $checker = $this->checker([AbuseIpDbProvider::com($transport, 'key')], breakerFailures: 2);

        $this->assertNull($checker->lookup('203.0.113.5'));
        $this->assertNull($checker->lookup('203.0.113.6'));
        // Breaker is open now: no third request leaves the process.
        $this->assertNull($checker->lookup('203.0.113.7'));
        $this->assertCount(2, $transport->requests);
    }

    public function testRateLimitWindowIsHonoured(): void
    {
        $transport = (new FakeTransport())->respond(429, '{"errors":[]}', ['retry-after' => '300']);
        $checker = $this->checker([AbuseIpDbProvider::com($transport, 'key')]);

        $this->assertNull($checker->lookup('203.0.113.5'));
        $this->assertNull($checker->lookup('203.0.113.6'));
        $this->assertCount(1, $transport->requests);
    }

    public function testInvalidAddressIsIgnoredWithoutNetwork(): void
    {
        $transport = new FakeTransport();
        $checker = $this->checker([AbuseIpDbProvider::com($transport, 'key')]);

        $this->assertNull($checker->lookup('not-an-ip'));
        $this->assertSame([], $transport->requests);
    }

    public function testProviderNamesAreExposed(): void
    {
        $checker = $this->checker([
            AbuseIpDbProvider::com(new FakeTransport(), 'a'),
            AbuseIpDbProvider::ru(new FakeTransport(), 'b'),
        ]);

        $this->assertSame(['abuseipdb.com', 'abuseipdb.ru'], $checker->providerNames());
    }

    /**
     * @param list<\Deynekin\PhpShield\ThreatIntel\ReputationProviderInterface> $providers
     */
    private function checker(array $providers, int $breakerFailures = 5): ReputationChecker
    {
        return new ReputationChecker($providers, new ArrayReputationCache(), 86400, $breakerFailures, 120);
    }

    private function payload(int $score): string
    {
        return (string) json_encode([
            'data' => [
                'ipAddress' => '203.0.113.5',
                'isWhitelisted' => false,
                'abuseConfidenceScore' => $score,
                'countryCode' => 'RU',
                'isp' => 'Example',
                'totalReports' => 3,
                'numDistinctUsers' => 2,
            ],
        ]);
    }
}
