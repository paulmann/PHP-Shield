<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests;

use Deynekin\PhpShield\Admin\AdminDashboard;
use Deynekin\PhpShield\Tests\Support\FakeSession;
use Deynekin\PhpShield\Tests\Support\InMemoryBlockStore;
use PHPUnit\Framework\TestCase;

class AdminDashboardTest extends TestCase
{
    private InMemoryBlockStore $store;

    private FakeSession $session;

    protected function setUp(): void
    {
        $this->store = new InMemoryBlockStore();
        $this->session = new FakeSession();
    }

    public function testAuthenticatesWithCorrectCredentials(): void
    {
        $dashboard = $this->dashboard();

        $this->assertTrue($dashboard->authenticate('admin', 'correct horse'));
        $this->assertTrue($dashboard->isAuthenticated());
    }

    public function testRejectsWrongPassword(): void
    {
        $dashboard = $this->dashboard();

        $this->assertFalse($dashboard->authenticate('admin', 'wrong'));
        $this->assertFalse($dashboard->isAuthenticated());
    }

    public function testRejectsLoginWhenPasswordHashIsEmpty(): void
    {
        $dashboard = $this->dashboard(['admin' => $this->adminConfig(['password_hash' => ''])]);

        $this->assertFalse($dashboard->authenticate('admin', 'anything'));
    }

    public function testLocksOutAfterFiveFailures(): void
    {
        $dashboard = $this->dashboard();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->assertFalse($dashboard->authenticate('admin', 'wrong'));
        }

        $this->assertGreaterThan(0, $dashboard->getLockoutRemaining());
        // Even the correct password is refused while the lockout is active.
        $this->assertFalse($dashboard->authenticate('admin', 'correct horse'));
    }

    public function testCsrfTokenIsStableAndRotates(): void
    {
        $dashboard = $this->dashboard();

        $token = $dashboard->csrfToken();
        $this->assertSame($token, $dashboard->csrfToken());
        $this->assertNotSame($token, $dashboard->rotateCsrfToken());
    }

    public function testValidatesOnlyTheCurrentToken(): void
    {
        $dashboard = $this->dashboard();
        $token = $dashboard->csrfToken();

        $this->assertTrue($dashboard->validateCsrfToken($token));
        $this->assertFalse($dashboard->validateCsrfToken(null));
        $this->assertFalse($dashboard->validateCsrfToken(''));
        $this->assertFalse($dashboard->validateCsrfToken('deadbeef'));

        $dashboard->rotateCsrfToken();
        $this->assertFalse($dashboard->validateCsrfToken($token));
    }

    public function testSafeConfigMasksCredentials(): void
    {
        $dashboard = $this->dashboard();

        $safe = $dashboard->getSafeConfig();

        $this->assertSame('[REDACTED]', $safe['admin']['password_hash']);
        $this->assertSame('[REDACTED]', $safe['redis']['password']);
    }

    public function testExpiredSessionIsNotAuthenticated(): void
    {
        $this->session->set('php_shield_admin_authenticated', true);
        $this->session->set('php_shield_admin_login_time', time() - 7200);

        $dashboard = $this->dashboard(['admin' => $this->adminConfig(['session_timeout' => 3600])]);

        $this->assertFalse($dashboard->isAuthenticated());
    }

    public function testDisabledAdminRefusesEverything(): void
    {
        $dashboard = $this->dashboard(['admin' => $this->adminConfig(['enabled' => false])]);

        $this->assertFalse($dashboard->authenticate('admin', 'correct horse'));
        $this->assertFalse($dashboard->isAuthenticated());
    }

    public function testBlockAndUnblockValidateTheAddress(): void
    {
        $dashboard = $this->dashboard();

        $this->assertFalse($dashboard->blockIp('not-an-ip', 'test'));
        $this->assertTrue($dashboard->blockIp('198.51.100.7', 'test', 60));
        $this->assertTrue($this->store->isBlocked('198.51.100.7'));

        $this->assertFalse($dashboard->unblockIp('not-an-ip'));
        $this->assertTrue($dashboard->unblockIp('198.51.100.7'));
        $this->assertFalse($this->store->isBlocked('198.51.100.7'));
    }

    public function testInvalidBlockTypeFallsBackToTemporary(): void
    {
        $dashboard = $this->dashboard();

        $dashboard->blockIp('198.51.100.9', 'test', 60, 'forever');

        $this->assertSame('temporary', $this->store->blocks['198.51.100.9']['type']);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function dashboard(array $overrides = []): AdminDashboard
    {
        $config = array_merge([
            'admin' => $this->adminConfig(),
            'mode' => 'monitor',
            'enabled_rules' => ['xss'],
            'rate_limiter' => 'database',
            'redis' => ['password' => 'redis-secret', 'host' => '127.0.0.1'],
        ], $overrides);

        return new AdminDashboard($this->store, $config, $this->session);
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function adminConfig(array $overrides = []): array
    {
        return array_merge([
            'enabled' => true,
            'username' => 'admin',
            'password_hash' => password_hash('correct horse', PASSWORD_DEFAULT),
            'session_name' => 'php_shield_admin',
            'session_timeout' => 3600,
            'cookie_samesite' => 'Strict',
            'cookie_secure' => null,
        ], $overrides);
    }
}
