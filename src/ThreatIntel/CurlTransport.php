<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\ThreatIntel;

use Deynekin\PhpShield\Exception\ThreatIntelException;

/**
 * cURL based transport with a hard timeout, TLS verification and no redirects.
 */
final class CurlTransport implements HttpTransportInterface
{
    public function __construct(private readonly string $userAgent = 'PHP-Shield/2.0')
    {
    }

    public function get(string $url, array $headers, float $timeout): array
    {
        if (!function_exists('curl_init')) {
            throw ThreatIntelException::unavailable('http transport', 'the curl extension is not available');
        }

        $handle = curl_init();

        if ($handle === false) {
            throw ThreatIntelException::unavailable('http transport', 'curl_init() failed');
        }

        $headerLines = [];

        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $responseHeaders = [];

        $timeoutMs = max(100, (int) round($timeout * 1000));

        curl_setopt_array($handle, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_HEADERFUNCTION => static function ($resource, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);

                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }

                return strlen($line);
            },
        ]);

        $body = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $errorNumber = curl_errno($handle);
        $error = curl_error($handle);

        curl_close($handle);

        if ($errorNumber !== 0 || !is_string($body)) {
            throw ThreatIntelException::unavailable('http transport', $error !== '' ? $error : 'request failed');
        }

        return ['status' => $status, 'body' => $body, 'headers' => $responseHeaders];
    }
}
