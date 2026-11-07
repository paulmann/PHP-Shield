<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\Tests\Support\FakeTransport;
use Deynekin\PhpShield\ThreatIntel\AbuseIpDbProvider;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationCache;
use Deynekin\PhpShield\ThreatIntel\ArrayReputationQueue;
use Deynekin\PhpShield\ThreatIntel\ReputationChecker;
use Deynekin\PhpShield\ThreatIntel\ReputationQueueInterface;
use Deynekin\PhpShield\ThreatIntel\ReputationWorker;
use PHPUnit\Framework\TestCase;

class ReputationWorkerTest extends TestCase
{
    public function testQueueDeduplicatesAddresses(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.5');
        $queue->push('203.0.113.5');

        $this->assertSame(1, $queue->size());
        $this->assertSame(['203.0.113.5'], $queue->claim(10));
    }

    public function testDrainsQueueAndFillsTheCache(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.5');

        $transport = (new FakeTransport())->respond(200, $this->payload(90));
        $checker = $this->checker($transport, $queue);
        $stats = (new ReputationWorker($queue, $checker, 50, 100, 300))->drain();

        $this->assertSame(1, $stats['processed']);
        $this->assertSame(1, $stats['fetched']);
        $this->assertSame(0, $stats['queued']);
        $this->assertCount(1, $transport->requests);

        // The request path now answers from the cache without any network call.
        $this->assertSame(90, $checker->lookup('203.0.113.5')?->abuseConfidenceScore);
        $this->assertCount(1, $transport->requests);
    }

    public function testFailedLookupStaysQueuedWithBackoff(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.5');

        $transport = (new FakeTransport())->respondWithException(
            ThreatIntelException::unavailable('abuseipdb.com', 'connection timed out')
        );
        $checker = $this->checker($transport, $queue);
        $worker = new ReputationWorker($queue, $checker, 50, 100, 300);

        $first = $worker->drain();

        $this->assertSame(1, $first['failed']);
        $this->assertSame(1, $first['queued']);

        // Not due yet: the second run must not touch the network again.
        $second = $worker->drain();

        $this->assertSame(0, $second['processed']);
        $this->assertCount(1, $transport->requests);
    }

    public function testEmptyAnswerRemovesTheAddressFromTheQueue(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.5');

        $transport = (new FakeTransport())->respond(422, '{"errors":[{"detail":"bad ip","status":422}]}');
        $stats = (new ReputationWorker($queue, $this->checker($transport, $queue)))->drain();

        $this->assertSame(1, $stats['empty']);
        $this->assertSame(0, $stats['queued']);
    }

    public function testPerRunBudgetLeavesTheRestQueued(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.1');
        $queue->push('203.0.113.2');
        $queue->push('203.0.113.3');

        $transport = (new FakeTransport())
            ->respond(200, $this->payload(10))
            ->respond(200, $this->payload(10))
            ->respond(200, $this->payload(10));

        $stats = (new ReputationWorker($queue, $this->checker($transport, $queue), 50, 1, 300))->drain();

        $this->assertSame(1, $stats['fetched']);
        $this->assertSame(2, $stats['skipped']);
        $this->assertSame(2, $stats['queued']);
        $this->assertCount(1, $transport->requests);
    }

    public function testDisabledCheckerDoesNothing(): void
    {
        $queue = new ArrayReputationQueue();
        $queue->push('203.0.113.5');

        $checker = new ReputationChecker([], new ArrayReputationCache(), 86400, 5, 120, $queue, true);
        $stats = (new ReputationWorker($queue, $checker))->drain();

        $this->assertSame(0, $stats['processed']);
        $this->assertSame(1, $queue->size());
    }

    public function testWorkerReportsQueueSize(): void
    {
        $queue = new ArrayReputationQueue();
        $checker = $this->checker(new FakeTransport(), $queue);

        $this->assertSame(0, (new ReputationWorker($queue, $checker))->drain()['queued']);
    }

    private function checker(FakeTransport $transport, ReputationQueueInterface $queue): ReputationChecker
    {
        return new ReputationChecker(
            [AbuseIpDbProvider::com($transport, 'test-key')],
            new ArrayReputationCache(),
            86400,
            5,
            120,
            $queue,
            true
        );
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
