<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Storage;

/**
 * Contract for IP block and incident storage.
 *
 * Blocks and incidents are separate concerns: this store keeps state, the
 * decision itself belongs to the shield/middleware layer.
 */
interface BlockStoreInterface
{
    public function isBlocked(string $ip): bool;

    public function isPermanentlyBlocked(string $ip): bool;

    /**
     * @param 'temporary'|'permanent' $type
     * @param string $severity one of: low, medium, high, critical
     */
    public function block(
        string $ip,
        string $reason,
        ?int $durationSeconds = null,
        string $type = 'temporary',
        string $severity = 'medium'
    ): void;

    public function unblock(string $ip): void;

    /**
     * @return list<array<string, mixed>>
     */
    public function getActiveBlocks(int $limit = 100): array;

    /**
     * @param array<string, mixed> $context
     */
    public function logIncident(
        string $ip,
        ?int $userId,
        string $type,
        string $description,
        string $severity,
        array $context = []
    ): void;

    /**
     * Number of incidents recorded for one address in the recent window.
     */
    public function countIncidents(string $ip, int $windowSeconds): int;

    /**
     * @return list<array<string, mixed>>
     */
    public function getRecentIncidents(int $limit = 50): array;

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array;
}
