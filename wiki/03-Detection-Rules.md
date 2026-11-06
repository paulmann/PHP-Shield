# Detection rules

## The six shipped rules

| Rule | Category | Scores | What it catches |
|---|---|---|---|
| `sql_injection` | injection | 50 `UNION SELECT`, 80 `DROP TABLE`, 60 `SLEEP(`, 30 tautology | stacked queries, time-based probes, `' OR 1=1` |
| `xss` | xss | 90 `<script>`, 70 `javascript:`, 60 event handler, 65 `eval(` | script injection, `onerror=`, `javascript:` URLs |
| `command_injection` | injection | 85 `system(`, 75 `; cat`, 70 pipes to commands, 60 backticked command | shell metacharacters aimed at an exec call |
| `path_traversal` | path | 95 `/etc/shadow`, 90 `/etc/passwd`, 60 repeated `../` | directory escape, sensitive file probes |
| `file_inclusion` | inclusion | 85 `php://filter`, 80 remote include, 75 `php://input` | wrapper abuse, RFI |
| `suspicious_header` | headers | 70 sqlmap/nikto/nmap, 60 masscan/zgrab | scanner User-Agents |

Values are tested four ways: as received, URL-decoded, after `stripslashes`, and with NUL bytes
removed. `REQUEST_URI` is scanned as well, so a payload that the router never passes to the
application is still seen.

## Scoring model

- a rule returns the first matching pattern per value, with its score and description;
- scores from different rules and different fields are summed;
- one finding per rule per field is recorded, so encoding a payload twice does not double the score;
- the sum is compared with `block_threshold` (50 by default) in `block` mode, and with
  `challenge_threshold` (30) in `challenge` mode;
- anything at or above `suspicious_threshold` (20) is journaled once per 10 minutes and never
  blocked on its own.

A single rule that matches once rarely crosses the threshold. That is deliberate: blocking is a sum
of evidence, not a single regex hit.

## Reading the journal to tune

```sql
SELECT incident_type, severity, COUNT(*) AS hits
FROM php_shield_incidents
WHERE occurred_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY incident_type, severity
ORDER BY hits DESC;
```

Then:

1. find the endpoint that produces the noise (`context` holds the endpoint and the field);
2. lower the rule score for that rule, or disable it: `rules.<name>.enabled = false`;
3. never raise `block_threshold` blindly — it hides real attacks along with the noise.

## False positives worth knowing

| Case | What happens | Fix |
|---|---|---|
| A security site accepts an abuse report containing `' UNION SELECT` | `sql_injection` scores high, the request is blocked in `block` mode | run that endpoint in `monitor` mode, or disable the rule for it |
| A CMS editor posts HTML with `onclick=` | `xss` fires on legitimate content | disable `xss` for the authenticated editor endpoint, keep it everywhere else |
| A file manager passes `../` in a legitimate path | `path_traversal` fires | normalise the path before the shield, or whitelist the endpoint |
| A monitoring robot uses a scanner-like User-Agent | `suspicious_header` fires | add the address to `trusted_ips` instead of weakening the rule |

Tuning per endpoint is done by calling `inspect()` with a different endpoint name and a configuration
that disables rules for it, or by scoring your own way and comparing with `block_threshold`.

## Writing a custom rule

```php
use Deynekin\PhpShield\Detection\AbstractRule;

final class MyRule extends AbstractRule
{
    public function getName(): string { return 'my_rule'; }
    public function getCategory(): string { return 'custom'; }

    public function check(string $value, string $fieldName): array
    {
        return $this->match('/evil/i', $value, $fieldName, 45, 'Custom evil pattern');
    }
}
```

Register it, then enable it:

```php
use Deynekin\PhpShield\Detection\RuleFactory;

RuleFactory::register('my_rule', MyRule::class);

$config['enabled_rules'][] = 'my_rule';
```

Requirements for a pull request that adds a rule:

1. a new class in `src/Detection/` extending `AbstractRule`;
2. `getName()`, `getCategory()`, `check()` implemented with `$this->match(...)`;
3. registration in `RuleFactory::RULE_MAP`, plus the name in `enabled_rules` **only if** the rule is
   safe by default;
4. **positive and negative** tests — a rule without a negative case is rejected;
5. the rule table updated in `README.md` (all six languages) and in this page.

Keep patterns conservative. A false positive in a security library is a customer outage; a false
negative is what the next layer exists for.
