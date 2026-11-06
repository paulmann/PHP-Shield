<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\Support;

use Deynekin\PhpShield\Storage\BlockStoreInterface;
use Deynekin\PhpShield\Storage\FailedAttemptStoreInterface;
use Deynekin\PhpShield\Storage\MaintenanceStoreInterface;

/**
 * In-memory block store so the shield can be tested without MySQL.
 */
final class InMemoryBlockStore implements BlockStoreInterface, FailedAttemptStoreInterface, MaintenanceStoreInterface
{
    /**
     * @var array<string, array{type: string, severity: string, reason: string, expiresAt: int|null}>
     */
    public array $blocks = [];

    /**
     * @var list<array{ip: string, type: string, description: string, severity: string, context: array<string, mixed>}>
     */
    public array $incidents = [];

    /**
     * @var array<string, int>
     */
    public array $attempts = [];

    public function isBlocked(string $ip): bool
    {
        $block = $this->blocks[$ip] ?? null;

        return $block !== null && ($block['expiresAt'] === null || $block['expiresAt'] > time());
    }

    public function isPermanentlyBlocked(string $ip): bool
    {
        $block = $this->blocks[$ip] ?? null;

        return $block !== null
            && $block['type'] === 'permanent'
            && ($block['expiresAt'] === null || $block['expiresAt'] > time());
    }

    public function block(
        string $ip,
        string $reason,
        ?int $durationSeconds = null,
        string $type = 'temporary',
        string $severity = 'medium'
    ): void {
        $this->blocks[$ip] = [
            'type' => $type,
            'severity' => $severity,
            'reason' => $reason,
            'expiresAt' => $durationSeconds !== null && $durationSeconds > 0 ? time() + $durationSeconds : null,
        ];
    }

    public function unblock(string $ip): void
    {
        unset($this->blocks[$ip]);
    }

    public function getActiveBlocks(int $limit = 100): array
    {
        $rows = [];

        foreach ($this->blocks as $ip => $block) {
            $rows[] = [
                'ip_address' => $ip,
                'block_type' => $block['type'],
                'severity' => $block['severity'],
                'reason' => $block['reason'],
                'expires_at' => $block['expiresAt'] === null ? null : date('Y-m-d H:i:s', $block['expiresAt']),
                'created_at' => date('Y-m-d H:i:s'),
            ];
        }

        return array_slice($rows, 0, $limit);
    }

    public function logIncident(
        string $ip,
        ?int $userId,
        string $type,
        string $description,
        string $severity,
        array $context = []
    ): void {
        $this->incidents[] = [
            'ip' => $ip,
            'type' => $type,
            'description' => $description,
            'severity' => $severity,
            'context' => $context,
        ];
    }

    public function countIncidents(string $ip, int $windowSeconds): int
    {
        $count = 0;

        foreach ($this->incidents as $incident) {
            if ($incident['ip'] === $ip) {
                $count++;
            }
        }

        return $count;
    }

    public function getRecentIncidents(int $limit = 50): array
    {
        return array_slice(array_reverse($this->incidents), 0, $limit);
    }

    public function recordFailedAttempt(string $ip): int
    {
        $this->attempts[$ip] = ($this->attempts[$ip] ?? 0) + 1;

        return $this->attempts[$ip];
    }

    public function getFailedAttempts(string $ip): int
    {
        return $this->attempts[$ip] ?? 0;
    }

    public function clearFailedAttempts(string $ip): void
    {
        unset($this->attempts[$ip]);
    }

    public function cleanup(int $retentionDays = 30): array
    {
        $deleted = ['blocks' => 0, 'incidents' => count($this->incidents), 'attempts' => count($this->attempts)];

        $this->incidents = [];
        $this->attempts = [];

        return $deleted;
    }

    public function getStats(): array
    {
        $byType = [];

        foreach ($this->incidents as $incident) {
            $byType[$incident['type']] = ($byType[$incident['type']] ?? 0) + 1;
        }

        return [
            'active_blocks' => count($this->blocks),
            'permanent_blocks' => 0,
            'incidents_24h' => count($this->incidents),
            'incidents_total' => count($this->incidents),
            'high_severity_7d' => 0,
            'by_type' => $byType,
            'top_ips' => [],
        ];
    }
}
