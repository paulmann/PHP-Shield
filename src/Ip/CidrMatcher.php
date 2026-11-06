<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Ip;

/**
 * IPv4 and IPv6 CIDR matching utilities.
 */
class CidrMatcher
{
    public static function ipInRange(string $ip, string $range): bool
    {
        if (!str_contains($range, '/')) {
            return $ip === $range;
        }

        [$subnet, $bitsStr] = explode('/', $range, 2);
        $bits = (int) $bitsStr;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $ipVersion = strlen($ipBin) === 4 ? 4 : 6;
        $subnetVersion = strlen($subnetBin) === 4 ? 4 : 6;

        if ($ipVersion !== $subnetVersion) {
            return false;
        }

        $maxBits = $ipVersion === 4 ? 32 : 128;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $bitsLeft = $bits % 8;

        if (substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }

        if ($bitsLeft > 0) {
            $mask = (0xff << (8 - $bitsLeft)) & 0xff;
            return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
        }

        return true;
    }

    /**
     * @param string[] $trustedRanges
     */
    public static function isTrusted(string $ip, array $trustedRanges): bool
    {
        foreach ($trustedRanges as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }
        return false;
    }
}
