![PHP Shield — modular request firewall for PHP](assets/social-preview.png)

# PHP Shield

**Модульный межсетевой экран запросов для PHP**: локальное обнаружение угроз, репутация IPv4/IPv6 (AbuseIPDB.com и AbuseIPDB.ru), ограничение частоты запросов, блокировка IP со сроками, зависящими от серьёзности, журнал инцидентов и панель администратора.

[English](README.md) · **Русский** · [Deutsch](README.de.md) · [Español](README.es.md) · [中文](README.zh.md) · [हिन्दी](README.hi.md)

[![CI](https://github.com/paulmann/PHP-Shield/actions/workflows/ci.yml/badge.svg)](https://github.com/paulmann/PHP-Shield/actions)
[![PHP Version](https://img.shields.io/badge/php-8.1--8.5-blue)](https://php.net)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%20max-brightgreen)](phpstan.neon)
[![Tests](https://img.shields.io/badge/tests-120-brightgreen)](tests)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Wiki](https://img.shields.io/badge/docs-wiki-blue)](https://github.com/paulmann/PHP-Shield/wiki)

## Содержание

- [Что он делает](#что-он-делает)
- [Как принимается решение по запросу](#как-принимается-решение-по-запросу)
- [Требования](#требования)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Массив решения](#массив-решения)
- [Репутация IP: AbuseIPDB.com и AbuseIPDB.ru](#репутация-ip-abuseipdbcom-и-abuseipdbru)
- [Правила обнаружения](#правила-обнаружения)
- [Режимы и сроки блокировки](#режимы-и-сроки-блокировки)
- [Ограничение частоты запросов](#ограничение-частоты-запросов)
- [API состояния](#api-состояния)
- [Панель администратора](#панель-администратора)
- [Обратные прокси и IP клиента](#обратные-прокси-и-ip-клиента)
- [Архитектура](#архитектура)
- [Тестирование](#тестирование)
- [Чек-лист для продакшена](#чек-лист-для-продакшена)
- [Документация](#документация)
- [Участие в разработке](#участие-в-разработке)
- [Лицензия](#лицензия)
- [Благодарности](#благодарности)

## Что он делает

Одна точка входа, `Deynekin\PhpShield\Middleware\Shield::inspect()`, отвечает на единственный вопрос: **может ли этот запрос быть обработан, и если нет, то почему?**

Он объединяет четыре слоя:

| Слой | Класс | Ответственность |
|---|---|---|
| Решение | `Middleware\Shield` | ограничения частоты, сканирование параметров и заголовков, репутация IP, вердикт |
| Состояние | `Middleware\SecurityMiddleware` | блокировки, журнал инцидентов, счётчики неудачных попыток, очистка, статистика |
| Обнаружение | `Detection\*` | подключаемые правила, оценивающие нагрузку |
| Знания | `ThreatIntel\*` | репутация AbuseIPDB.com / AbuseIPDB.ru с кэшем и размыкателем цепи |

Два правила определяют каждое решение:

- **Одна находка никогда никого не блокирует.** Баллы накапливаются, и блокирует только сумма выше `block_threshold`. О постоянной блокировке решает оператор, а не регулярное выражение.
- **Ничто не переходит в закрытое состояние при сбое инфраструктуры.** Недоступность базы данных или API означает «нет данных», а не «запретить» — см. [ADR-006](docs/adr.md).

Чем щит **не** является: заменой подготовленных выражений, экранирования вывода, CSP, аутентификации или безопасности сессий. Он выигрывает время и даёт наблюдаемость; дефекты приложения он не исправляет.

## Как принимается решение по запросу

`inspect()` проходит слои в фиксированном порядке: сначала дешёвые проверки, сеть — последней, а доверенный адрес выходит из схемы до любой работы. Любая ветка заканчивается одним и тем же массивом решения: `blocked`, `status`, `reason`, `detail`, `score` и `findings`.

```mermaid
flowchart TD
    REQ(["HTTP-запрос"]) --> INSPECT["Shield::inspect()"]
    INSPECT --> ENABLED{"включён?"}
    ENABLED -->|нет| ALLOW(["разрешено"])
    ENABLED -->|да| TRUSTED{"IP клиента в trusted_ips?"}
    TRUSTED -->|да, не считается| ALLOW
    TRUSTED -->|нет| BLOCKED{"адрес заблокирован?"}
    BLOCKED -->|да| DENY403["403 ip_blocked"]
    BLOCKED -->|нет| FAILS{"счётчик неудач исчерпан?"}
    FAILS -->|да| BLOCK1["блокировка один раз"]
    BLOCK1 --> DENY403B["403 too_many_failures"]
    FAILS -->|нет| RATE{"лимит частоты превышен?"}
    RATE -->|да| BLOCK2["блокировка 300 с"]
    BLOCK2 --> DENY429["429 rate_limited"]
    RATE -->|нет| REPUTATION["репутация IP: кэш, резервный провайдер, предохранитель"]
    REPUTATION --> SCORED{"оценка злоупотреблений"}
    SCORED -->|block_score и выше| BLOCK3["блокировка и инцидент"]
    BLOCK3 --> DENY403C["403 ip_reputation"]
    SCORED -->|flag_score и выше| JOURNAL1["только журнал"]
    JOURNAL1 --> SCAN["проверка данных: 6 правил по GET, POST, REQUEST_URI"]
    SCORED -->|ниже, нет данных или сбой| SCAN
    SCAN --> FINDING{"оценка"}
    FINDING -->|режим block, порог достигнут| BLOCK4["журнал и блокировка"]
    BLOCK4 --> DENY403D["403 threat_detected"]
    FINDING -->|режим challenge, порог достигнут| DENY403E["403 challenge_required"]
    FINDING -->|подозрительно| JOURNAL2["журнал раз в 10 минут"]
    JOURNAL2 --> HEADERS["проверка заголовков: User-Agent"]
    FINDING -->|чисто| HEADERS
    HEADERS -->|сканер| JOURNAL3["журнал или блокировка"]
    HEADERS -->|чисто| ALLOW
    JOURNAL3 --> ALLOW
    ALLOW --> DECISION["массив решения: blocked, status, reason, detail, score, findings"]
    DENY403 --> DECISION
    DENY403B --> DECISION
    DENY429 --> DECISION
    DENY403C --> DECISION
    DENY403D --> DECISION
    DENY403E --> DECISION
    DECISION --> APP(["приложение или ответ с ошибкой"])
    classDef allow fill:#d3f9d8,stroke:#2f9e44,color:#000000
    classDef deny fill:#ffe3e3,stroke:#c92a2a,color:#000000
    classDef step fill:#e7f5ff,stroke:#1c7ed6,color:#000000
    class ALLOW,APP allow
    class DENY403,DENY403B,DENY429,DENY403C,DENY403D,DENY403E deny
    class INSPECT,SCAN,DECISION step
```

Ветвление по режимам стоит рядом с оценкой, а не в начале схемы: `monitor` и `challenge` меняют реакцию на находку, но не порядок проверок.

## Требования

- PHP 8.1 – 8.5, `ext-json`, `ext-mbstring`
- Опционально: `ext-mysqli` (хранилище MySQL, админка), `ext-redis` (лимитер Redis), `ext-curl` (репутация IP)

## Установка

```bash
composer require paulmann/php-shield
```

## Быстрый старт

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

Нет MySQL? Тогда соберите щит из компонентов — локальное обнаружение, заголовки и статистика продолжат работать:

```php
$shield = ShieldFactory::createWithComponents(
    $blockStore,                                  // your BlockStoreInterface implementation
    new \Deynekin\PhpShield\RateLimiting\RedisRateLimiter($redis),
    $config
);
```

## Массив решения

`inspect()` возвращает:

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

Причины: `ip_blocked`, `too_many_failures`, `rate_limited`, `ip_reputation`, `threat_detected`, `challenge_required`, `suspicious_user_agent`.

Порядок проверок фиксирован и намеренен: главный переключатель → доверенный адрес (никогда не блокируется, никогда не учитывается) → активная блокировка → счётчик неудачных попыток → ограничения частоты → репутация IP → сканирование параметров → сканирование заголовков → пропуск.

Если нужно только логическое значение, вызовите `isRequestAllowed()` с теми же аргументами.

# README i18n ru — run 78725121 participant 4

## IP reputation: AbuseIPDB.com and AbuseIPDB.ru

Оба сервиса реализуют один и тот же контракт API v2 (`/check`, заголовок `Key:`, идентичные конверты), поэтому один клиент обслуживает оба, а проверяющий обращается к ним по очереди.

Слой репутации **по умолчанию работает асинхронно**: запрос никогда не ждёт AbuseIPDB. Известный адрес берётся из кеша, неизвестный ставится в очередь одним `INSERT`, а воркер наполняет кеш вне основного потока. Переключайтесь на `'mode' => 'sync'` только для низконагруженных эндпоинтов, тестов или CLI-инструментов.

| Режим | Путь запроса | Когда применяется вердикт |
|---|---|---|
| `async` (по умолчанию) | чтение кеша плюс не более одного `INSERT` в `php_shield_reputation_queue` | начиная со следующего запроса после того, как воркер сохранил ответ |
| `sync` | один HTTP-вызов, ограниченный `timeout` | немедленно |

```bash
# cron: fill the reputation cache every minute
* * * * * php /path/to/PHP-Shield/tools/reputation-worker.php >> /var/log/php-shield-reputation.log 2>&1

php tools/reputation-worker.php --status         # queue size and providers
php tools/reputation-worker.php --ip=8.8.8.8     # one address now (debugging)
```

```php
$config['ip_reputation'] = [
    'enabled' => true,
    'block_score' => 75,   // abuseConfidenceScore that blocks
    'flag_score' => 25,    // score that is only journaled
    'cache_ttl' => 86400,
    'max_age_days' => 90,
    'timeout' => 2,        // sync mode only
    'queue_batch' => 50,   // addresses claimed per worker run
    'per_run' => 100,      // lookups per worker run (quota guard)
    'retry_after' => 300,  // retry delay after a failed lookup
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

Что важно в продакшене:

- ответы кешируются на `cache_ttl` секунд — всплеск запросов стоит одного обращения, и спрашивают только о публичных адресах;
- воркер соблюдает `per_run`, поэтому дневная квота расходуется постепенно, а не одним всплеском;
- неудачный поиск остаётся в очереди с задержкой `retry_after` — сбой API не может раскрутить воркер;
- первый визит нового адреса никогда не задерживается и не блокируется *из-за* AbuseIPDB: слой репутации подтверждает или снимает его на следующем запросе (ADR-010);
- побеждает первый провайдер, который ответил; если он失敗ил, пробуется следующий;
- `429` никогда не повторяется внутри процесса: объявленное окно соблюдается для всех последующих поисков;
- после `circuit_breaker.failures` подряд идущих ошибок провайдер пропускается на `cooldown` секунд;
- ответ `null`, таймаут или ошибка квоты никогда не блокируют запрос;
- в режиме `monitor` высокий балл журналируется, но не блокируется.

## Правила обнаружения

| Правило | Категория | Баллы | Примечания |
|---|---|---|---|
| `sql_injection` | инъекция | 25–80 | `UNION SELECT`, многостатементные запросы, `SLEEP`, тавтологии |
| `xss` | xss | 40–90 | теги script/iframe/object, обработчики событий, `javascript:` |
| `command_injection` | инъекция | 60–85 | семейство `system()`, конвейеры в команды, обратные кавычки команд |
| `path_traversal` | путь | 60–95 | повторяющиеся `../`, `/etc/passwd`, `.ssh`, `/proc/self` |
| `file_inclusion` | включение | 60–85 | удалённые включения, обёртки `php://` |
| `suspicious_header` | заголовки | 60–70 | User-Agent сканеров (sqlmap, nikto, nmap, …) |

Значения сканируются как есть и после URL-декодирования, а также сырой `REQUEST_URI`, поэтому `%3Cscript%3E` перехватывается. По каждому правилу и полю фиксируется одна находка, поэтому дважды закодированная нагрузка не может завысить свой балл.

### Свои правила

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

## Режимы и сроки блокировки

| Режим | Поведение |
|---|---|
| `monitor` | всё пишется в журнал, ничего не блокируется |
| `challenge` | жёсткие находки отклоняются с 403 `challenge_required` и не блокируются |
| `block` | жёсткие находки блокируют адрес на срок, производный от серьёзности |

Срок = `block_duration` × `severity_block_multipliers`:

| Серьёзность | Множитель | Срок по умолчанию |
|---|---|---|
| `low` | 0.5 | 30 мин |
| `medium` | 1 | 1 ч |
| `high` | 4 | 4 ч |
| `critical` | 12 | 12 ч |

У ограничения частоты своё короткое окно (`rate_limit_block_duration`, 300 с), чтобы всплеск с общего/NAT-адреса не заблокировал весь офис. Постоянная блокировка никогда не наступает автоматически: это действие оператора в панели или вызов `blockPermanently()`.

## Ограничение частоты запросов

| Бэкенд | Как считает | Когда использовать |
|---|---|---|
| `DatabaseRateLimiter` | два запроса (подсчёт, вставка) к `php_shield_rate_limit` | низкий и средний трафик; вызывайте `prune()` по расписанию |
| `RedisRateLimiter` | атомарные `INCR` + `EXPIRE` | конкурентный трафик; при недоступности Redis работает fail open и пишет в лог |

Ограничения по умолчанию — 60/минуту, 1 000/час и 10 000/сутки на адрес и эндпоинт. Оба бэкенда реализуют `RateLimiterInterface`, поэтому можно подключить уже имеющийся лимитер.

## API состояния

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

Когда счётчик неудачных попыток достигает `max_failed_attempts` (25), следующий запрос с этого адреса блокируется один раз, а счётчик очищается.

Таблицы: `php_shield_ip_blocks`, `php_shield_incidents`, `php_shield_failed_attempts`, `php_shield_rate_limit`, `php_shield_ip_reputation`. Все сроки истечения вычисляет база данных (`NOW()`, `DATE_ADD`), поэтому расхождение часовых поясов PHP и MySQL не может погасить свежую блокировку.

## Панель администратора

`public/admin/index.php` — статистика, активные блокировки, ручная блокировка и разблокировка, конфигурация с маскированием.

- каждая форма, меняющая состояние, несёт посессионный анти-CSRF токен;
- вход ограничен по частоте (5 неудач → блокировка на 5 мин), идентификатор сессии перегенерируется при входе;
- cookie сессии — `HttpOnly`, `SameSite=Strict`, `Secure` на HTTPS;
- дамп конфигурации маскирует пароли, токены и ключи перед отображением.

Сгенерируйте хэш и дополнительно защитите эндпоинт на уровне веб-сервера:

```bash
php -r "echo password_hash('your-secret', PASSWORD_DEFAULT), PHP_EOL;"
```

## Обратные прокси и IP клиента

`X-Forwarded-For` учитывается, только если `REMOTE_ADDR` входит в `trusted_proxies`, и цепочка читается **справа налево**, пропуская доверенные шаги:

```text
X-Forwarded-For: 1.2.3.4, 203.0.113.9      (client-supplied, added by nginx)
REMOTE_ADDR:     10.0.0.5                  (trusted proxy)
→ client = 203.0.113.9
```

Чтение крайнего левого элемента позволило бы любому клиенту выбрать себе адрес — а при совпадении с записью в `trusted_ips` и обойти весь щит. Это был реальный дефект, исправленный в 2.0.0 и описанный в [обзоре безопасности](docs/security-review.md).

## Архитектура

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

Проектные решения, альтернативы и их последствия записаны в [docs/adr.md](docs/adr.md).

## Тестирование

```bash
composer test          # PHPUnit, 120 tests, no database needed
composer phpstan       # level max, zero errors
composer cs-check      # coding standard

# real MySQL (creates its own tables, never drops a database)
MYSQL_PWD=... php -d extension=mysqli tools/db-selftest.php php_shield_test

# live AbuseIPDB check (key from the environment)
ABUSEIPDB_API_KEY=[redacted] php tools/live-abuseipdb.php 8.8.8.8
```

CI прогоняет PHP 8.1 – 8.5, PHPUnit, PHPStan уровня max, стандарт кодирования и проверку синтаксиса каждого PHP-файла.

## Чек-лист для продакшена

1. Поработайте несколько дней в режиме `monitor`.
2. Прочитайте `php_shield_incidents` и настройте `block_threshold` / отключите шумные правила.
3. Примените `migrations/schema.sql` и установите `auto_migrate` в `false`.
4. Переведите лимитер на Redis для конкурентного трафика.
5. Заполните `trusted_proxies`, если вы за обратным прокси — forwarded-заголовки принимаются **только** от этих адресов, и цепочка читается справа налево.
6. Защитите панель администратора; задайте стойкий хэш пароля.
7. Запланируйте `cleanup()` (сроки хранения) и `DatabaseRateLimiter::prune()`.
8. Включите `ip_reputation` с AbuseIPDB.com, оставив AbuseIPDB.ru как резерв.
9. Добавьте `SecurityHeaders::send()` в начале обработки запроса.
10. Переключитесь в режим `block` и сутки наблюдайте за долей 403/429.

## Документация

- [Wiki](https://github.com/paulmann/PHP-Shield/wiki) — справочник по конфигурации, рецепты, устранение неполадок, руководство по обновлению
- [Записи архитектурных решений](docs/adr.md)
- [Обзор безопасности](docs/security-review.md) — находки и их исправления
- [Эталонный адаптер](integration/abuseipdb-ru/README.md) — замена написанного вручную middleware AbuseIPDB.RU этим пакетом
- [SECURITY.md](SECURITY.md) — как сообщить об уязвимости
- [AGENTS.md](AGENTS.md) — инструкции для ИИ-агентов разработки

## Участие в разработке

Сначала прочитайте [CONTRIBUTING.md](CONTRIBUTING.md): стандарт кодирования, статический анализ, тесты и чек-лист ревью. Issues и pull requests приветствуются; отчёты об уязвимостях — через [SECURITY.md](SECURITY.md).

## Лицензия

MIT — см. [LICENSE](LICENSE).

## Благодарности

Создан Михаилом Дейнекиным. Политика серьёзности и разделение состояния и обнаружения сложились под влиянием отдельного middleware, применявшегося на AbuseIPDB.RU, и WAF проекта PHP-Form-Spam-Checker.

---

[English](README.md) · **Русский** · [Deutsch](README.de.md) · [Español](README.es.md) · [中文](README.zh.md) · [हिन्दी](README.hi.md)
