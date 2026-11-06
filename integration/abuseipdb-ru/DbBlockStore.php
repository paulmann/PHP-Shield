<?php

/**
 * Reference adapter: PHP Shield storage over the AbuseIPDB.RU platform database.
 *
 * The site already owns the tables created by migration 033
 * (`security_ip_blocks`, `security_incidents`, `security_failed_attempts`), so
 * this store maps the library contract onto them instead of asking for a
 * second schema. No data migration is needed.
 *
 * Copy it into the project as `src/Security/Protect/DbBlockStore.php`.
 */

declare(strict_types=1);

namespace Iya\Security\Protect;

use Deynekin\PhpShield\Storage\BlockStoreInterface;
use Deynekin\PhpShield\Storage\FailedAttemptStoreInterface;
use Deynekin\PhpShield\Storage\MaintenanceStoreInterface;
use Iya\Infrastructure\Db\Db;
use Iya\Infrastructure\Log\Logger;

final class DbBlockStore implements BlockStoreInterface, FailedAttemptStoreInterface, MaintenanceStoreInterface
{
    private const SEVERITIES = ['low', 'medium', 'high', 'critical'];

    public function __construct(
        private readonly Db $db,
        private readonly ?Logger $logger = null,
    ) {
    }

    public function isBlocked(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        $row = $this->db->fetch('SELECT kind, blocked_until FROM security_ip_blocks WHERE ip = ? LIMIT 1', [$ip]);

        if ($row === null) {
            return false;
        }

        if ((string) ($row['kind'] ?? '') === 'permanent') {
            return true;
        }

        $until = (string) ($row['blocked_until'] ?? '');

        if ($until === '') {
            return true;
        }

        $timestamp = strtotime($until);

        return $timestamp !== false && $timestamp > time();
    }

    public function isPermanentlyBlocked(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        $row = $this->db->fetch(
            'SELECT blocked_until FROM security_ip_blocks WHERE ip = ? AND kind = ? LIMIT 1',
            [$ip, 'permanent'],
        );

        if ($row === null) {
            return false;
        }

        $until = (string) ($row['blocked_until'] ?? '');

        if ($until === '') {
            return true;
        }

        $timestamp = strtotime($until);

        return $timestamp !== false && $timestamp > time();
    }

    public function block(
        string $ip,
        string $reason,
        ?int $durationSeconds = null,
        string $type = 'temporary',
        string $severity = 'medium'
    ): void {
        if ($ip === '') {
            return;
        }

        $kind = $type === 'permanent' ? 'permanent' : 'temporary';
        $severity = in_array($severity, self::SEVERITIES, true) ? $severity : 'medium';
        $now = gmdate('Y-m-d H:i:s');
        $until = $kind === 'permanent' || $durationSeconds === null || $durationSeconds <= 0
            ? null
            : gmdate('Y-m-d H:i:s', time() + $durationSeconds);

        $existing = $this->db->fetch('SELECT id FROM security_ip_blocks WHERE ip = ? LIMIT 1', [$ip]);

        if ($existing !== null) {
            $this->db->execute(
                'UPDATE security_ip_blocks SET kind = ?, reason = ?, severity = ?, blocked_until = ?, updated_at = ? WHERE ip = ?',
                [$kind, mb_substr($reason, 0, 240), $severity, $until, $now, $ip],
            );

            return;
        }

        $this->db->insert('security_ip_blocks', [
            'ip' => $ip,
            'kind' => $kind,
            'reason' => mb_substr($reason, 0, 240),
            'severity' => $severity,
            'blocked_until' => $until,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    public function unblock(string $ip): void
    {
        $this->db->execute('DELETE FROM security_ip_blocks WHERE ip = ?', [$ip]);
    }

    public function getActiveBlocks(int $limit = 100): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM security_ip_blocks ORDER BY id DESC LIMIT ' . max(1, min(500, $limit)),
        );
    }

    public function logIncident(
        string $ip,
        ?int $userId,
        string $type,
        string $description,
        string $severity,
        array $context = []
    ): void {
        $severity = in_array($severity, self::SEVERITIES, true) ? $severity : 'medium';

        $patterns = null;

        if ($context !== []) {
            $encoded = json_encode(
                $context,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR,
            );
            $patterns = is_string($encoded) ? mb_substr($encoded, 0, 2000) : null;
        }

        $this->db->insert('security_incidents', [
            'ip' => mb_substr($ip, 0, 100),
            'user_id' => $userId,
            'incident_type' => mb_substr($type, 0, 64),
            'description' => mb_substr($description, 0, 1000),
            'severity' => $severity,
            'patterns' => $patterns,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);
    }

    public function countIncidents(string $ip, int $windowSeconds): int
    {
        $since = gmdate('Y-m-d H:i:s', time() - max(1, $windowSeconds));

        return (int) $this->db->fetchColumn(
            'SELECT COUNT(*) FROM security_incidents WHERE ip = ? AND created_at >= ?',
            [$ip, $since],
        );
    }

    public function getRecentIncidents(int $limit = 50): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM security_incidents ORDER BY id DESC LIMIT ' . max(1, min(500, $limit)),
        );
    }

    public function recordFailedAttempt(string $ip): int
    {
        $now = gmdate('Y-m-d H:i:s');
        $row = $this->db->fetch('SELECT ip FROM security_failed_attempts WHERE ip = ? LIMIT 1', [$ip]);

        if ($row === null) {
            $this->db->insert('security_failed_attempts', [
                'ip' => $ip,
                'attempts' => 1,
                'last_attempt_at' => $now,
            ]);

            return 1;
        }

        $this->db->execute(
            'UPDATE security_failed_attempts SET attempts = attempts + 1, last_attempt_at = ? WHERE ip = ?',
            [$now, $ip],
        );

        return $this->getFailedAttempts($ip);
    }

    public function getFailedAttempts(string $ip): int
    {
        return (int) $this->db->fetchColumn(
            'SELECT attempts FROM security_failed_attempts WHERE ip = ? LIMIT 1',
            [$ip],
        );
    }

    public function clearFailedAttempts(string $ip): void
    {
        $this->db->execute('DELETE FROM security_failed_attempts WHERE ip = ?', [$ip]);
    }

    public function cleanup(int $retentionDays = 30): array
    {
        $blockCutoff = gmdate('Y-m-d H:i:s');
        $incidentCutoff = gmdate('Y-m-d H:i:s', time() - max(1, $retentionDays) * 86400);
        $attemptCutoff = gmdate('Y-m-d H:i:s', time() - 86400);

        return [
            'blocks' => $this->db->execute(
                'DELETE FROM security_ip_blocks WHERE kind = ? AND blocked_until IS NOT NULL AND blocked_until < ?',
                ['temporary', $blockCutoff],
            ),
            'incidents' => $this->db->execute(
                'DELETE FROM security_incidents WHERE created_at < ?',
                [$incidentCutoff],
            ),
            'attempts' => $this->db->execute(
                'DELETE FROM security_failed_attempts WHERE last_attempt_at < ?',
                [$attemptCutoff],
            ),
        ];
    }

    public function getStats(): array
    {
        $now = gmdate('Y-m-d H:i:s');

        return [
            'active_blocks' => (int) $this->db->fetchColumn(
                'SELECT COUNT(*) FROM security_ip_blocks WHERE kind = ? OR blocked_until > ?',
                ['permanent', $now],
            ),
            'permanent_blocks' => (int) $this->db->fetchColumn(
                'SELECT COUNT(*) FROM security_ip_blocks WHERE kind = ?',
                ['permanent'],
            ),
            'incidents_24h' => (int) $this->db->fetchColumn(
                'SELECT COUNT(*) FROM security_incidents WHERE created_at >= ?',
                [gmdate('Y-m-d H:i:s', time() - 86400)],
            ),
            'incidents_total' => (int) $this->db->fetchColumn('SELECT COUNT(*) FROM security_incidents'),
            'high_severity_7d' => (int) $this->db->fetchColumn(
                "SELECT COUNT(*) FROM security_incidents WHERE severity IN ('high','critical') AND created_at >= ?",
                [gmdate('Y-m-d H:i:s', time() - 7 * 86400)],
            ),
            'by_type' => $this->db->fetchAll(
                'SELECT incident_type, COUNT(*) AS hits FROM security_incidents GROUP BY incident_type ORDER BY hits DESC LIMIT 20',
            ),
            'top_ips' => $this->db->fetchAll(
                'SELECT ip, COUNT(*) AS hits FROM security_incidents GROUP BY ip ORDER BY hits DESC LIMIT 10',
            ),
        ];
    }
}
