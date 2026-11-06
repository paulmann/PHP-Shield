<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Storage;

/**
 * Optional capability: retention cleanup of expired state.
 */
interface MaintenanceStoreInterface
{
    /**
     * Delete expired temporary blocks, old incidents and stale attempt counters.
     *
     * @return array<string, int> rows deleted per table
     */
    public function cleanup(int $retentionDays = 30): array;
}
