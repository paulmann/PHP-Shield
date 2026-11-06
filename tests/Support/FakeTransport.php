<?php

declare(strict_types=1);

namespace Deynekin\PhpShield\Tests\Support;

use Deynekin\PhpShield\Exception\ThreatIntelException;
use Deynekin\PhpShield\ThreatIntel\HttpTransportInterface;

/**
 * Scripted HTTP transport: returns queued responses and records requests.
 */
final class FakeTransport implements HttpTransportInterface
{
    /**
     * @var list<array{status: int, body: string, headers: array<string, string>}>
     */
    private array $responses = [];

    /**
     * @var list<array{url: string, headers: array<string, string>}>
     */
    public array $requests = [];

    /**
     * @param array{status: int, body: string, headers: array<string, string>} $response
     */
    public function queue(array $response): self
    {
        $this->responses[] = $response;

        return $this;
    }

    /**
     * @param array<string, string> $headers
     */
    public function respond(int $status, string $body, array $headers = []): self
    {
        return $this->queue(['status' => $status, 'body' => $body, 'headers' => $headers]);
    }

    public function respondWithException(ThreatIntelException $exception): self
    {
        $this->responses[] = ['status' => -1, 'body' => $exception->getMessage(), 'headers' => []];

        return $this;
    }

    public function get(string $url, array $headers, float $timeout): array
    {
        $this->requests[] = ['url' => $url, 'headers' => $headers];

        $response = array_shift($this->responses);

        if ($response === null) {
            throw ThreatIntelException::unavailable('fake transport', 'no queued response');
        }

        if ($response['status'] === -1) {
            throw ThreatIntelException::unavailable('fake transport', $response['body']);
        }

        return $response;
    }
}
