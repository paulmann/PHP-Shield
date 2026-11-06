<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\Tests\Support\FakeTransport;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use PHPUnit\Framework\TestCase;

class AbuseIpDbProviderTest extends TestCase
{
    /**
     * Real abuseipdb.com v2 answer for 8.8.8.8 (project sample).
     */
    private const CHECK_8888 = '{"data":{"ipAddress":"8.8.8.8","isPublic":true,"ipVersion":4,"isWhitelisted":true,'
        . '"abuseConfidenceScore":0,"countryCode":"US","usageType":"Content Delivery Network","isp":"Google LLC",'
        . '"domain":"google.com","hostnames":["dns.google"],"isTor":false,"totalReports":67,'
        . '"numDistinctUsers":26,"lastReportedAt":"2026-11-06T18:39:06+00:00"}}';

    private const ERROR_NO_KEY = '{"errors":[{"detail":"Authentication failed. Your API key is either missing, '
        . 'incorrect, or revoked.","status":401}]}';

    public function testParsesRealCheckPayload(): void
    {
        $transport = (new FakeTransport())->respond(200, self::CHECK_8888);

        $reputation = AbuseIpDbProvider::com($transport, 'test-key')->lookup('8.8.8.8');

        $this->assertNotNull($reputation);
        $this->assertSame('8.8.8.8', $reputation->ip);
        $this->assertSame('abuseipdb.com', $reputation->provider);
        $this->assertSame(0, $reputation->abuseConfidenceScore);
        $this->assertTrue($reputation->isWhitelisted);
        $this->assertSame('Google LLC', $reputation->isp);
        $this->assertSame(67, $reputation->totalReports);
        $this->assertSame('US', $reputation->countryCode);
    }

    public function testSendsKeyHeaderAndQueryParameters(): void
    {
        $transport = (new FakeTransport())->respond(200, '{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":80}}');

        AbuseIpDbProvider::ru($transport, 'ru-key', 30)->lookup('203.0.113.9');

        $request = $transport->requests[0];

        $this->assertSame(
            'https://abuseipdb.ru/api/v2/check?ipAddress=203.0.113.9&maxAgeInDays=30',
            $request['url']
        );
        $this->assertSame('ru-key', $request['headers']['Key']);
        $this->assertSame('application/json', $request['headers']['Accept']);
    }

    public function testComBaseUrlIsTheDefault(): void
    {
        $transport = (new FakeTransport())->respond(200, '{"data":{}}');

        AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9');

        $this->assertStringStartsWith('https://api.abuseipdb.com/api/v2/check?', $transport->requests[0]['url']);
    }

    public function testPrivateAddressesAreNotQueried(): void
    {
        $transport = new FakeTransport();

        $this->assertNull(AbuseIpDbProvider::com($transport, 'key')->lookup('192.168.1.1'));
        $this->assertNull(AbuseIpDbProvider::com($transport, 'key')->lookup('127.0.0.1'));
        $this->assertNull(AbuseIpDbProvider::com($transport, 'key')->lookup('not-an-ip'));
        $this->assertSame([], $transport->requests);
    }

    public function testEmptyApiKeyThrows(): void
    {
        $this->expectException(ThreatIntelException::class);
        AbuseIpDbProvider::com(new FakeTransport(), '')->lookup('8.8.8.8');
    }

    public function testAuthenticationFailureIsLoud(): void
    {
        $transport = (new FakeTransport())->respond(401, self::ERROR_NO_KEY);

        $this->expectException(ThreatIntelException::class);
        $this->expectExceptionMessage('authentication failed');
        AbuseIpDbProvider::com($transport, 'bad-key')->lookup('8.8.8.8');
    }

    public function testInvalidAddressResponseMeansNoOpinion(): void
    {
        $transport = (new FakeTransport())->respond(422, '{"errors":[{"detail":"bad ip","status":422}]}');

        $this->assertNull(AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9'));
    }

    public function testRateLimitCarriesRetryAfter(): void
    {
        $transport = (new FakeTransport())->respond(429, '{"errors":[]}', ['retry-after' => '120']);

        try {
            AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9');
            $this->fail('Expected a rate-limit exception');
        } catch (ThreatIntelException $exception) {
            $this->assertSame(120, $exception->getRetryAfter());
        }
    }

    public function testRateLimitFallsBackToRateLimitResetHeader(): void
    {
        $reset = (string) (time() + 300);
        $transport = (new FakeTransport())->respond(429, '{"errors":[]}', ['x-ratelimit-reset' => $reset]);

        try {
            AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9');
            $this->fail('Expected a rate-limit exception');
        } catch (ThreatIntelException $exception) {
            $this->assertGreaterThan(200, $exception->getRetryAfter());
        }
    }

    public function testServerErrorIsUnavailable(): void
    {
        $transport = (new FakeTransport())->respond(503, 'service unavailable');

        $this->expectException(ThreatIntelException::class);
        AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9');
    }

    public function testBrokenJsonIsUnavailable(): void
    {
        $transport = (new FakeTransport())->respond(200, '<html>not json</html>');

        $this->expectException(ThreatIntelException::class);
        AbuseIpDbProvider::com($transport, 'key')->lookup('203.0.113.9');
    }

    public function testProviderNameIsReported(): void
    {
        $this->assertSame('abuseipdb.com', AbuseIpDbProvider::com(new FakeTransport(), 'key')->name());
        $this->assertSame('abuseipdb.ru', AbuseIpDbProvider::ru(new FakeTransport(), 'key')->name());
    }
}
