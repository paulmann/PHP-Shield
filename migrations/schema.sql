-- PHP-Shield database schema
--
-- Tables are also created automatically on first use (config key
-- auto_migrate). For production, apply this file once and set
-- 'auto_migrate' => false so no DDL runs on the request path.
--
-- Keep this file in sync with src/Storage/MysqlBlockStore.php,
-- src/RateLimiting/DatabaseRateLimiter.php and
-- src/ThreatIntel/MysqlReputationCache.php.

CREATE TABLE IF NOT EXISTS php_shield_ip_blocks (
    ip_address VARCHAR(45) NOT NULL PRIMARY KEY,
    block_type ENUM('temporary', 'permanent') NOT NULL DEFAULT 'temporary',
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
    reason VARCHAR(255) NULL,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL,
    KEY idx_expires (expires_at),
    KEY idx_block_type (block_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS php_shield_incidents (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    user_id INT UNSIGNED NULL,
    incident_type VARCHAR(64) NOT NULL,
    description TEXT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
    context JSON NULL,
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_ip_time (ip_address, occurred_at),
    KEY idx_type_severity (incident_type, severity),
    KEY idx_occurred (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS php_shield_failed_attempts (
    ip_address VARCHAR(45) NOT NULL PRIMARY KEY,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at DATETIME NOT NULL,
    KEY idx_last_attempt (last_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS php_shield_rate_limit (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    rate_key VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    KEY idx_key_time (rate_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Shared cache for IP reputation readings (AbuseIPDB.com / AbuseIPDB.ru) and
-- the circuit-breaker state.
CREATE TABLE IF NOT EXISTS php_shield_ip_reputation (
    cache_key VARCHAR(190) NOT NULL PRIMARY KEY,
    payload JSON NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Upgrade path from 1.x (blocks table without severity):
--   ALTER TABLE php_shield_ip_blocks
--       ADD COLUMN severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium'
--       AFTER block_type;

-- Maintenance, to be scheduled (cron / event scheduler):
--   DELETE FROM php_shield_rate_limit WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 DAY);
--   DELETE FROM php_shield_ip_blocks WHERE block_type = 'temporary' AND expires_at <= NOW();
--   DELETE FROM php_shield_incidents WHERE occurred_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
--   DELETE FROM php_shield_failed_attempts WHERE last_attempt_at < DATE_SUB(NOW(), INTERVAL 1 DAY);
--   DELETE FROM php_shield_ip_reputation WHERE expires_at <= NOW();
