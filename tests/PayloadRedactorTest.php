<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Support\PayloadRedactor;
use PHPUnit\Framework\TestCase;

class PayloadRedactorTest extends TestCase
{
    public function testRedactsSensitiveKeys(): void
    {
        $input = [
            'username' => 'alice',
            'password' => 'secret123',
            'api_token' => 'abc-def',
            'nested' => [
                'credit_card' => '4111111111111111',
                'comment' => 'hello',
            ],
        ];

        $result = PayloadRedactor::redact($input);

        $this->assertSame('alice', $result['username']);
        $this->assertSame('[REDACTED]', $result['password']);
        $this->assertSame('[REDACTED]', $result['api_token']);
        $this->assertSame('[REDACTED]', $result['nested']['credit_card']);
        $this->assertSame('hello', $result['nested']['comment']);
    }

    public function testTruncatesLongStrings(): void
    {
        $long = str_repeat('a', 300);
        $result = PayloadRedactor::redact(['body' => $long]);

        $this->assertStringEndsWith('...[truncated]', $result['body']);
        $this->assertLessThan(250, strlen($result['body']));
    }

    public function testStopsAtMaximumDepth(): void
    {
        $deep = 'leaf';

        for ($i = 0; $i < 20; $i++) {
            $deep = ['level' => $deep];
        }

        $encoded = json_encode(PayloadRedactor::redact(['deep' => $deep]));

        $this->assertIsString($encoded);
        $this->assertStringContainsString('DEPTH_LIMIT_REACHED', $encoded);
    }

    public function testReplacesObjectsInsteadOfLeakingThem(): void
    {
        $result = PayloadRedactor::redact(['object' => new \stdClass()]);

        $this->assertSame('[OBJECT stdClass]', $result['object']);
    }

    public function testPreservesInvalidUtf8WithoutThrowing(): void
    {
        $binary = "\xB1\x31";

        $result = PayloadRedactor::redact(['raw' => $binary]);

        $this->assertSame($binary, $result['raw']);
    }

    public function testKeepsNumericKeysAndValues(): void
    {
        $result = PayloadRedactor::redact(['items' => [0 => 'a', 1 => 'b']]);

        $this->assertSame(['a', 'b'], $result['items']);
    }
}
