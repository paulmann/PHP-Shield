<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Ip;

/**
 * Safely resolves the client IP address.
 *
 * Forwarded headers are honoured only when the direct peer is a configured
 * trusted proxy, and the chain is walked from right to left: entries appended
 * by our own proxies are trustworthy, anything further left is client supplied.
 * Reading the left-most entry instead would let any client choose its own IP.
 */
class IpResolver
{
    private const HEADER_FORWARDED_FOR = 'HTTP_X_FORWARDED_FOR';
    private const HEADER_REAL_IP = 'HTTP_X_REAL_IP';
    private const UNKNOWN_IP = '0.0.0.0';

    /**
     * @param list<string> $trustedProxies
     */
    public function __construct(
        private readonly array $trustedProxies = []
    ) {
    }

    /**
     * @param array<string, mixed> $server
     */
    public function resolve(array $server): string
    {
        $remoteAddr = $this->normalize($this->read($server, 'REMOTE_ADDR'));

        if (!$this->isTrustedProxy($remoteAddr)) {
            return $this->asValidIp($remoteAddr);
        }

        $chain = $this->forwardedChain($server);

        // Right to left: the closest hop that is not one of our proxies is the client.
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if (!$this->isTrustedProxy($chain[$i])) {
                return $chain[$i];
            }
        }

        if ($chain !== []) {
            // Every hop is a trusted proxy: the left-most entry is our best guess.
            return $chain[0];
        }

        $realIp = $this->normalize($this->read($server, self::HEADER_REAL_IP));

        if (filter_var($realIp, FILTER_VALIDATE_IP) !== false) {
            return $realIp;
        }

        return $this->asValidIp($remoteAddr);
    }

    /**
     * @param array<string, mixed> $server
     * @return list<string>
     */
    private function forwardedChain(array $server): array
    {
        $raw = $this->read($server, self::HEADER_FORWARDED_FOR);

        if (trim($raw) === '') {
            return [];
        }

        $chain = [];

        foreach (explode(',', $raw) as $part) {
            $candidate = $this->normalize($part);

            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                $chain[] = $candidate;
            }
        }

        return $chain;
    }

    /**
     * @param array<string, mixed> $server
     */
    private function read(array $server, string $key): string
    {
        $value = $server[$key] ?? null;

        if (is_string($value)) {
            return $value;
        }

        return is_int($value) ? (string) $value : '';
    }

    private function isTrustedProxy(string $ip): bool
    {
        return $this->trustedProxies !== [] && CidrMatcher::isTrusted($ip, $this->trustedProxies);
    }

    private function asValidIp(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : self::UNKNOWN_IP;
    }

    private function normalize(string $ip): string
    {
        $ip = trim($ip, " \t\n\r\0\x0B\"'[]");

        // Strip an IPv6 zone identifier, e.g. fe80::1%eth0
        if (str_contains($ip, '%')) {
            $ip = explode('%', $ip, 2)[0];
        }

        // Strip an IPv4 port, e.g. 203.0.113.5:5678 (IPv6 has several colons)
        if (substr_count($ip, ':') === 1 && preg_match('/^(?<address>[0-9.]+):\d+$/', $ip, $matches) === 1) {
            $ip = $matches['address'];
        }

        return $ip;
    }
}
