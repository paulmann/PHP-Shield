<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

/**
 * In-process queue: fine for tests, single-run tools and CLI workers, but it
 * does not survive the request that filled it — use MysqlReputationQueue when
 * the enqueue and the worker live in different processes.
 */
final class ArrayReputationQueue implements ReputationQueueInterface
{
    /**
     * @var array<string, array{attempts: int, dueAt: int}>
     */
    private array $entries = [];

    public function push(string $ip): void
    {
        if ($ip === '' || isset($this->entries[$ip])) {
            return;
        }

        $this->entries[$ip] = ['attempts' => 0, 'dueAt' => time()];
    }

    public function claim(int $limit): array
    {
        $due = [];
        $now = time();

        foreach ($this->entries as $ip => $entry) {
            if ($entry['dueAt'] > $now) {
                continue;
            }

            $due[] = $ip;

            if (count($due) >= max(1, $limit)) {
                break;
            }
        }

        return $due;
    }

    public function complete(string $ip): void
    {
        unset($this->entries[$ip]);
    }

    public function fail(string $ip, string $error, int $retryAfterSeconds = 300): void
    {
        if (!isset($this->entries[$ip])) {
            return;
        }

        $this->entries[$ip] = [
            'attempts' => $this->entries[$ip]['attempts'] + 1,
            'dueAt' => time() + max(1, $retryAfterSeconds),
        ];
    }

    public function size(): int
    {
        return count($this->entries);
    }
}
