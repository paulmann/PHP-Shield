<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Admin;

use Deynekin\PhpShield\Exception\ConfigurationException;
use Deynekin\PhpShield\Ip\CidrMatcher;
use Deynekin\PhpShield\Ip\IpResolver;
use Deynekin\PhpShield\Support\Config;

/**
 * IP allowlist for the admin dashboard.
 *
 * Disabled by default: an empty `admin.allowed_ips` lets everyone reach the
 * login form (which still needs the password hash). As soon as one entry is
 * configured the gate is on, and an address outside the list gets a 403 before
 * the dashboard touches the database.
 *
 * IPv4 and IPv6 CIDR are both supported, `1.2.3.4` means `/32`. The client
 * address is resolved through IpResolver, so `X-Forwarded-For` is honoured only
 * from a configured trusted proxy — otherwise every visitor could claim an
 * allowlisted address with one header.
 */
final class AdminAccess
{
    private readonly Config $config;

    private readonly IpResolver $resolver;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [], ?IpResolver $resolver = null)
    {
        $this->config = Config::fromArray($config);
        $this->resolver = $resolver ?? new IpResolver($this->config->stringList('trusted_proxies'));
    }

    /**
     * @return list<string>
     */
    public function allowedIps(): array
    {
        $value = $this->config->raw('admin.allowed_ips', []);

        // A single string is convenient for environment-driven configuration:
        // "10.0.0.0/8, 192.168.0.0/16".
        if (is_string($value)) {
            $value = preg_split('/[\s,]+/', $value) ?: [];
        }

        if (!is_array($value)) {
            throw new ConfigurationException("Configuration key 'admin.allowed_ips' must be an array of CIDR strings.");
        }

        $list = [];

        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new ConfigurationException("Configuration key 'admin.allowed_ips' must contain only strings.");
            }

            $item = trim($item);

            if ($item !== '') {
                $list[] = $item;
            }
        }

        return $list;
    }

    /**
     * Is the allowlist active? An empty list means "no restriction".
     */
    public function isEnabled(): bool
    {
        return $this->allowedIps() !== [];
    }

    public function allows(string $ip): bool
    {
        if (!$this->isEnabled()) {
            return true;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return CidrMatcher::isTrusted($ip, $this->allowedIps());
    }

    /**
     * @param array<string, mixed> $server
     */
    public function allowsRequest(array $server): bool
    {
        return $this->allows($this->clientIp($server));
    }

    /**
     * @param array<string, mixed> $server
     */
    public function clientIp(array $server): string
    {
        return $this->resolver->resolve($server);
    }
}
