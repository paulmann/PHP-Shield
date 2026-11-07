<?php
declare(strict_types=1);

return [
    // Master switch for the whole shield.
    'enabled' => true,

    // monitor | challenge | block
    // Start with 'monitor' and switch to 'block' only after reviewing the
    // incidents table: signature detection needs tuning per application.
    'mode' => 'monitor',

    'enable_content_scanning' => true,
    'enable_header_scanning' => true,

    // Scan REQUEST_URI as well as GET/POST: parameters that never reach the
    // application (routing, rewrites) still hit the server.
    'scan_request_uri' => true,

    // Score thresholds
    'block_threshold' => 50,
    'challenge_threshold' => 30,
    'suspicious_threshold' => 20, // journaled once per 10 minutes, never blocked

    // Block durations (seconds)
    'block_duration' => 3600,
    'rate_limit_block_duration' => 300,
    'max_failed_attempts' => 25,

    // Block lifetime per severity = block_duration × multiplier.
    // A permanent block is never automatic — use the admin or blockPermanently().
    'severity_block_multipliers' => [
        'low' => 0.5,      // 30 min
        'medium' => 1.0,   // 1 h
        'high' => 4.0,     // 4 h
        'critical' => 12.0 // 12 h
    ],

    // Create the tables on first use. Set to false in production and apply
    // migrations/schema.sql instead, so no DDL runs on the request path.
    'auto_migrate' => true,

    // Loopback only by default. Add your office/monitoring ranges explicitly:
    // every address listed here bypasses all checks.
    'trusted_ips' => [
        '127.0.0.1',
        '::1'
    ],

    // Only these addresses may set X-Forwarded-For / X-Real-IP
    'trusted_proxies' => [
        // '10.0.0.1',
        // '172.16.0.0/12'
    ],

    'rate_limits' => [
        'minute' => ['limit' => 60, 'window' => 60],
        'hour' => ['limit' => 1000, 'window' => 3600],
        'day' => ['limit' => 10000, 'window' => 86400]
    ],

    // Which detection rules to load
    'enabled_rules' => [
        'sql_injection',
        'xss',
        'command_injection',
        'path_traversal',
        'file_inclusion',
        'suspicious_header'
    ],

    // Per-rule overrides
    'rules' => [
        'sql_injection' => ['enabled' => true],
        'xss' => ['enabled' => true],
        'command_injection' => ['enabled' => true],
        'path_traversal' => ['enabled' => true],
        'file_inclusion' => ['enabled' => true],
        'suspicious_header' => ['enabled' => true]
    ],

    // IP reputation via AbuseIPDB.
    //
    // abuseipdb.ru implements the same API v2 contract as abuseipdb.com
    // (same paths, same `Key:` header, same envelopes), so both are listed as
    // providers and the checker tries them in order. Keys are read from the
    // environment when api_key is left empty — never commit a real key.
    //
    // mode:
    //   'async' (default) — the request path never calls the API: a known
    //     address is answered from the cache, an unknown one is queued and the
    //     worker (tools/reputation-worker.php, cron every minute) fills the
    //     cache. Nothing on the request path can be delayed by AbuseIPDB.
    //   'sync' — the lookup happens inline, bounded by `timeout`. Only for
    //     low-traffic endpoints or CLI tools.
    'ip_reputation' => [
        'enabled' => false,
        'mode' => 'async',
        'block_score' => 75, // abuseConfidenceScore that blocks
        'flag_score' => 25,  // score that is only journaled
        'cache_ttl' => 86400,
        'max_age_days' => 90,
        'timeout' => 2,
        'queue_batch' => 50, // addresses claimed per worker run
        'per_run' => 100,    // lookups per worker run (quota guard)
        'retry_after' => 300, // retry delay for a failed lookup
        'circuit_breaker' => [
            'failures' => 5,
            'cooldown' => 120
        ],
        'providers' => [
            [
                'name' => 'abuseipdb.com',
                'base_url' => 'https://api.abuseipdb.com/api/v2',
                'api_key' => null,
                'api_key_env' => 'ABUSEIPDB_API_KEY'
            ],
            [
                'name' => 'abuseipdb.ru',
                'base_url' => 'https://abuseipdb.ru/api/v2',
                'api_key' => null,
                'api_key_env' => 'ABUSEIPDB_RU_API_KEY'
            ]
        ]
    ],

    // Admin dashboard credentials
    'admin' => [
        'enabled' => true,
        'username' => 'admin',
        // Generate with: php -r "echo password_hash('your-secret', PASSWORD_DEFAULT);"
        // An empty hash disables login entirely.
        'password_hash' => '',
        'session_name' => 'php_shield_admin',
        'session_timeout' => 3600,
        'cookie_samesite' => 'Strict',
        // null = decide from $_SERVER['HTTPS']
        'cookie_secure' => null,
        // IP allowlist for the dashboard. DISABLED by default (an empty list
        // means no restriction). Fill it to restrict the panel to known
        // networks; an address outside the list gets 403 before the dashboard
        // touches the database. Forwarded headers are honoured only from
        // `trusted_proxies` above.
        'allowed_ips' => [
            // '203.0.113.0/24',
            // '198.51.100.7',
        ]
    ],

    // Rate limiter driver: 'database' or 'redis'
    'rate_limiter' => 'database',

    'redis' => [
        'host' => '127.0.0.1',
        'port' => 6379,
        'password' => null,
        'database' => 0,
        'prefix' => 'phpshield:rl:'
    ]
];
