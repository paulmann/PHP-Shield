![PHP Shield — modular request firewall for PHP](assets/social-preview.png)

# PHP Shield

**面向 PHP 的模块化请求防火墙**：本地威胁检测、IPv4/IPv6 信誉查询（AbuseIPDB.com 与 AbuseIPDB.ru）、速率限制、按严重级别决定封禁时长的 IP 封禁、事件日志以及管理后台。

[English](README.md) · [Русский](README.ru.md) · [Deutsch](README.de.md) · [Español](README.es.md) · **中文** · [हिन्दी](README.hi.md)

[![CI](https://github.com/paulmann/PHP-Shield/actions/workflows/ci.yml/badge.svg)](https://github.com/paulmann/PHP-Shield/actions)
[![PHP Version](https://img.shields.io/badge/php-8.1--8.5-blue)](https://php.net)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%20max-brightgreen)](phpstan.neon)
[![Tests](https://img.shields.io/badge/tests-120-brightgreen)](tests)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue)](https://github.com/paulmann/PHP-Shield/wiki)

## 目录

- [功能说明](#功能说明)
- [环境要求](#环境要求)
- [安装](#安装)
- [快速开始](#快速开始)
- [决策数组](#决策数组)
- [IP 信誉数据源 AbuseIPDB.com 与 AbuseIPDB.ru](#ip-信誉数据源-abuseipdbcom-与-abuseipdbru)
- [检测规则](#检测规则)
- [运行模式与封禁时长](#运行模式与封禁时长)
- [速率限制](#速率限制)
- [状态 API](#状态-api)
- [管理后台](#管理后台)
- [反向代理与客户端 IP](#反向代理与客户端-ip)
- [架构](#架构)
- [测试](#测试)
- [上线检查清单](#上线检查清单)
- [文档](#文档)
- [贡献](#贡献)
- [许可证](#许可证)
- [致谢](#致谢)

## 功能说明

唯一的入口 `Deynekin\PhpShield\Middleware\Shield::inspect()` 只回答一个问题：**这个请求可以继续吗，如果不可以，为什么？**

它把四层组合在一起：

| 层 | 类 | 职责 |
|---|---|---|
| 决策 | `Middleware\Shield` | 速率限制、载荷与请求头扫描、IP 信誉、最终裁决 |
| 状态 | `Middleware\SecurityMiddleware` | 封禁、事件日志、失败尝试计数、清理、统计 |
| 检测 | `Detection\*` | 可插拔规则，为载荷打分 |
| 知识 | `ThreatIntel\*` | AbuseIPDB.com / AbuseIPDB.ru 信誉查询，含缓存与熔断器 |

有两条规则贯穿每一次决策：

- **单条命中永远不会封禁任何人。** 分数会累加，只有总分超过 `block_threshold` 才会封禁。永久封禁由运维人员决定，而不是由正则表达式决定。
- **遇到基础设施故障时绝不失败关闭。** 数据库或 API 中断意味着“没有数据”，而不是“拒绝”——参见 [ADR-006](docs/adr.md)。

PHP Shield **不是**什么：它不能替代预处理语句、输出转义、CSP、身份认证或会话安全。它换来的是时间与可见性，而不是修复应用本身的缺陷。

## 环境要求

- PHP 8.1 – 8.5，`ext-json`，`ext-mbstring`
- 可选：`ext-mysqli`（MySQL 存储、管理后台），`ext-redis`（Redis 速率限制器），`ext-curl`（IP 信誉查询）

## 安装

```bash
composer require paulmann/php-shield
```

## 快速开始

```php
<?php
require 'vendor/autoload.php';

use Deynekin\PhpShield\ShieldFactory;

$config = require 'vendor/paulmann/php-shield/config/default.php';
$config['mode'] = 'monitor';              // start safe, switch to "block" after tuning

$mysqli = new mysqli('127.0.0.1', 'user', 'pass', 'dbname');
$shield = ShieldFactory::create($config, $mysqli);

$decision = $shield->inspect(array_merge($_GET, $_POST), $_SERVER, $_SERVER['REQUEST_URI'] ?? '/');

if ($decision['blocked']) {
    http_response_code($decision['status']);
    header('Content-Type: application/json');
    exit(json_encode(['error' => $decision['reason'], 'detail' => $decision['detail']]));
}

// Application logic continues...
```

没有 MySQL？改为用各组件自行拼装——本地检测、请求头处理和统计依然可用：

```php
$shield = ShieldFactory::createWithComponents(
    $blockStore,                                  // your BlockStoreInterface implementation
    new \Deynekin\PhpShield\RateLimiting\RedisRateLimiter($redis),
    $config
);
```

## 决策数组

`inspect()` 返回：

```php
[
    'blocked'  => true,                 // may the request proceed?
    'status'   => 403,                  // HTTP status to send
    'reason'   => 'threat_detected',    // machine-readable code
    'detail'   => '...',                // human-readable text
    'score'    => 90,                   // accumulated score
    'findings' => ['xss', 'sql_injection'],
]
```

原因码：`ip_blocked`、`too_many_failures`、`rate_limited`、`ip_reputation`、`threat_detected`、`challenge_required`、`suspicious_user_agent`。

检查顺序是固定且有意的：总开关 → 受信任地址（永不封禁、永不计入统计）→ 当前生效的封禁 → 失败尝试计数器 → 速率限制 → IP 信誉 → 载荷扫描 → 请求头扫描 → 放行。

如果只需要一个布尔结果，可以用相同的参数调用 `isRequestAllowed()`。

## IP 信誉数据源 AbuseIPDB.com 与 AbuseIPDB.ru

两个服务实现相同的 API v2 约定（`/check`、`Key:` 请求头、完全一致的响应信封），因此一个客户端即可同时对接两者，检查器会按顺序依次尝试。

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'block_score' => 75,   // abuseConfidenceScore that blocks
    'flag_score' => 25,    // score that is only journaled
    'cache_ttl' => 86400,
    'timeout' => 2,
    'providers' => [
        ['name' => 'abuseipdb.com', 'base_url' => 'https://api.abuseipdb.com/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_API_KEY'],
        ['name' => 'abuseipdb.ru',  'base_url' => 'https://abuseipdb.ru/api/v2',
         'api_key' => null, 'api_key_env' => 'ABUSEIPDB_RU_API_KEY'],
    ],
];
```

```bash
export ABUSEIPDB_API_KEY=[redacted]          # or put the key in the config, never in git
php tools/live-abuseipdb.php 8.8.8.8
```

生产环境中需要关注的行为：

- 结果会缓存 `cache_ttl` 秒——一阵突发流量只消耗一次查询，并且只会对公网地址发起查询；
- 第一个返回结果的提供商胜出；如果它失败，则尝试下一个；
- `429` 不会在进程内重试：后续所有查询都会遵守对方声明的窗口期；
- 连续出现 `circuit_breaker.failures` 次错误后，该提供商会在 `cooldown` 秒内被跳过；
- `null` 结果、超时或配额错误都不会导致请求被拦截；
- 在 `monitor` 模式下，高分会写入日志，但不会封禁。

## 检测规则

| 规则 | 类别 | 分值 | 说明 |
|---|---|---|---|
| `sql_injection` | 注入 | 25–80 | `UNION SELECT`、堆叠查询、`SLEEP`、恒真条件 |
| `xss` | xss | 40–90 | script/iframe/object 标签、事件处理器、`javascript:` |
| `command_injection` | 注入 | 60–85 | `system()` 系列函数、管道到命令、命令反引号 |
| `path_traversal` | 路径 | 60–95 | 重复的 `../`、`/etc/passwd`、`.ssh`、`/proc/self` |
| `file_inclusion` | 包含 | 60–85 | 远程包含、`php://` 包装器 |
| `suspicious_header` | 请求头 | 60–70 | 扫描器 User-Agent（sqlmap、nikto、nmap 等） |

值会同时以接收到的原始形式、URL 解码后的形式以及原始 `REQUEST_URI` 进行扫描，因此 `%3Cscript%3E` 也能被捕获。每条规则对每个字段只记录一次命中，所以二次编码的载荷无法虚增自己的分值。

### 自定义规则

```php
use Deynekin\PhpShield\Detection\AbstractRule;
use Deynekin\PhpShield\Detection\RuleFactory;

final class MyRule extends AbstractRule
{
    public function getName(): string { return 'my_rule'; }
    public function getCategory(): string { return 'custom'; }

    public function check(string $value, string $fieldName): array
    {
        return $this->match('/evil/i', $value, $fieldName, 45, 'Custom evil pattern');
    }
}

RuleFactory::register('my_rule', MyRule::class);
```

## 运行模式与封禁时长

| 模式 | 行为 |
|---|---|
| `monitor` | 一切都会写入日志，不做任何封禁 |
| `challenge` | 严重命中会以 403 `challenge_required` 拒绝，但不封禁 |
| `block` | 严重命中会按严重级别对应的时长封禁该地址 |

封禁时长 = `block_duration` × `severity_block_multipliers`：

| 严重级别 | 倍数 | 默认时长 |
|---|---|---|
| `low` | 0.5 | 30 分钟 |
| `medium` | 1 | 1 小时 |
| `high` | 4 | 4 小时 |
| `critical` | 12 | 12 小时 |

速率限制有自己独立的短窗口（`rate_limit_block_duration`，300 秒），这样来自共享/NAT 地址的突发流量就不会把整个办公室锁在门外。永久封禁永远不会自动发生：它只能由运维人员在后台执行，或通过调用 `blockPermanently()` 完成。

## 速率限制

| 后端 | 计数方式 | 适用场景 |
|---|---|---|
| `DatabaseRateLimiter` | 在 `php_shield_rate_limit` 上执行两条语句（计数、插入） | 低到中等流量；需要按计划调用 `prune()` |
| `RedisRateLimiter` | 原子 `INCR` + `EXPIRE` | 高并发流量；Redis 不可达时失败开放并记录日志 |

默认限制为每个地址、每个端点 60 次/分钟、1 000 次/小时和 10 000 次/天。两个后端都实现了 `RateLimiterInterface`，因此可以接入已有的限流器。

## 状态 API

```php
$state = $shield->middleware();

$state->isIpBlocked('203.0.113.5');
$state->blockIp('203.0.113.5', 'scanner', SecurityMiddleware::SEVERITY_HIGH);
$state->blockPermanently('203.0.113.5', 'manual decision');   // operator only
$state->unblockIp('203.0.113.5');

$state->recordFailedAttempt('203.0.113.5');   // e.g. from your login handler
$state->failedAttempts('203.0.113.5');
$state->clearFailedAttempts('203.0.113.5');

$state->recordIncident('203.0.113.5', 'login_bruteforce', 'Ten failed logins', 'high');
$state->recentIncidentCount('203.0.113.5', 600);
$state->activeBlocks(50);
$state->stats();
$state->cleanup(30);        // retention: expired blocks, old incidents, stale counters
```

当失败尝试计数器达到 `max_failed_attempts`（25）时，来自该地址的下一个请求会被封禁一次，随后计数器清零。

数据表：`php_shield_ip_blocks`、`php_shield_incidents`、`php_shield_failed_attempts`、`php_shield_rate_limit`、`php_shield_ip_reputation`。所有过期时间都由数据库计算（`NOW()`、`DATE_ADD`），因此 PHP 与 MySQL 之间的时区差异不会让刚建立的封禁提前失效。

## 管理后台

`public/admin/index.php`——统计信息、当前生效的封禁、手动封禁/解封、脱敏后的配置。

- 每个会改变状态的表单都带有按会话生成的防 CSRF 令牌；
- 登录受速率限制（5 次失败 → 锁定 5 分钟），登录时会重新生成会话 ID；
- 会话 Cookie 设置了 `HttpOnly`、`SameSite=Strict`，在 HTTPS 下为 `Secure`；
- 配置导出在渲染前会对密码、令牌和密钥做脱敏处理。

生成密码哈希，并在 Web 服务器层面也对该端点加以保护：

```bash
php -r "echo password_hash('your-secret', PASSWORD_DEFAULT), PHP_EOL;"
```

## 反向代理与客户端 IP

只有当 `REMOTE_ADDR` 位于 `trusted_proxies` 中时才会采信 `X-Forwarded-For`，并且链是**从右向左**读取的，会跳过受信任的跳点：

```text
X-Forwarded-For: 1.2.3.4, 203.0.113.9      (client-supplied, added by nginx)
REMOTE_ADDR:     10.0.0.5                  (trusted proxy)
→ client = 203.0.113.9
```

如果改为读取最左侧的条目，任何客户端都能自行选择地址——若再配上一条与之匹配的 `trusted_ips` 记录，就能绕过整个防护。这是一个真实存在的缺陷，已在 2.0.0 中修复，并记录在[安全审查](docs/security-review.md)中。

## 架构

```text
src/
├── ShieldFactory.php              ← wiring from configuration
├── Middleware/
│   ├── Shield.php                 ← decision: inspect() / isRequestAllowed()
│   └── SecurityMiddleware.php     ← state: blocks, incidents, counters, cleanup
├── Detection/                     ← rules + registry
├── ThreatIntel/                   ← AbuseIPDB.com / .ru, cache, circuit breaker
├── Ip/                            ← safe client IP resolution, CIDR
├── RateLimiting/                  ← database + Redis limiters
├── Storage/                       ← block store interfaces + MySQL
├── Admin/                         ← dashboard logic, sessions, CSRF
├── Support/                       ← typed config, redaction, headers
└── Exception/
```

设计决策、备选方案及其后果记录在 [docs/adr.md](docs/adr.md) 中。

## 测试

```bash
composer test          # PHPUnit, 120 tests, no database needed
composer phpstan       # level max, zero errors
composer cs-check      # coding standard

# real MySQL (creates its own tables, never drops a database)
MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test

# live AbuseIPDB check (key from the environment)
ABUSEIPDB_API_KEY=[redacted] php tools/live-abuseipdb.php 8.8.8.8
```

CI 会运行 PHP 8.1 – 8.5、PHPUnit、PHPStan 最高级别、编码规范检查，并对每个 PHP 文件做语法检查。

## 上线检查清单

1. 先在 `monitor` 模式下运行几天。
2. 查看 `php_shield_incidents`，调整 `block_threshold` / 关闭噪音较大的规则。
3. 执行 `migrations/schema.sql`，并把 `auto_migrate` 设为 `false`。
4. 面向高并发流量时，把速率限制器切换为 Redis。
5. 如果位于反向代理之后，请填写 `trusted_proxies`——转发头**仅**从这些地址采信，且链是从右向左读取的。
6. 保护管理后台；设置一个强密码哈希。
7. 为 `cleanup()`（保留期清理）和 `DatabaseRateLimiter::prune()` 安排定时任务。
8. 通过 AbuseIPDB.com 启用 `ip_reputation`，把 AbuseIPDB.ru 留作回退。
9. 在请求处理的早期加入 `SecurityHeaders::send()`。
10. 切换到 `block` 模式，并观察一天的 403/429 比率。

## 文档

- [Wiki](https://github.com/paulmann/PHP-Shield/wiki)——配置参考、实战配方、故障排查、升级指南
- [架构决策记录](docs/adr.md)
- [安全审查](docs/security-review.md)——发现的问题及其修复
- [参考适配器](integration/abuseipdb-ru/README.md)——用本包替换手写的 AbuseIPDB.RU 中间件
- [SECURITY.md](SECURITY.md)——如何报告漏洞
- [AGENTS.md](AGENTS.md)——面向 AI 编码代理的说明

## 贡献

请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)：编码规范、静态分析、测试和评审清单。欢迎提交 Issue 和 Pull Request；安全报告请通过 [SECURITY.md](SECURITY.md) 提交。

## 许可证

MIT——参见 [LICENSE](LICENSE)。

## 致谢

由 Mikhail Deynekin 构建。严重级别策略以及状态与检测的职责划分，源自在 AbuseIPDB.RU 上使用的独立中间件，以及 PHP-Form-Spam-Checker 的 WAF。

---

[English](README.md) · [Русский](README.ru.md) · [Deutsch](README.de.md) · [Español](README.es.md) · **中文** · [हिन्दी](README.hi.md)
