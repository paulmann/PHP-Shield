<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Throwable;

/**
 * Drains the reputation queue outside the request path.
 *
 * Run it from cron every minute:
 *
 *   * * * * * php /path/to/PHP-Shield/tools/reputation-worker.php
 *
 * The worker respects the provider quota: `perRun` limits the number of
 * lookups per run, and whatever is left stays queued for the next run. A
 * failed lookup is retried later with backoff, so one broken provider cannot
 * spin the queue.
 */
final class ReputationWorker
{
    public function __construct(
        private readonly ReputationQueueInterface $queue,
        private readonly ReputationChecker $checker,
        private readonly int $batchSize = 50,
        private readonly int $perRun = 100,
        private readonly int $retryAfterSeconds = 300
    ) {
    }

    /**
     * @return array{processed: int, fetched: int, empty: int, failed: int, skipped: int, queued: int}
     */
    public function drain(): array
    {
        $stats = ['processed' => 0, 'fetched' => 0, 'empty' => 0, 'failed' => 0, 'skipped' => 0, 'queued' => 0];

        if (!$this->checker->isEnabled()) {
            return $stats;
        }

        $budget = $this->perRun > 0 ? $this->perRun : PHP_INT_MAX;

        foreach ($this->queue->claim(max(1, $this->batchSize)) as $ip) {
            if ($stats['fetched'] + $stats['empty'] + $stats['failed'] >= $budget) {
                // The queue keeps the address; the next run continues here.
                $stats['skipped']++;

                continue;
            }

            $stats['processed']++;

            try {
                $reputation = $this->checker->fetchOrThrow($ip);
            } catch (Throwable $exception) {
                $stats['failed']++;
                $this->queue->fail($ip, $exception->getMessage(), $this->retryAfterSeconds);

                continue;
            }

            if ($reputation instanceof IpReputation) {
                $stats['fetched']++;
            } else {
                $stats['empty']++;
            }

            $this->queue->complete($ip);
        }

        $stats['queued'] = $this->queue->size();

        return $stats;
    }
}
