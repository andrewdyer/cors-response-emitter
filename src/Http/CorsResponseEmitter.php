<?php

declare(strict_types=1);

namespace YourVendor\YourPackage\Http;

use Psr\Http\Message\ResponseInterface;
use Slim\ResponseEmitter;

/**
 * Emits HTTP responses with CORS and cache-control headers applied.
 *
 * Centralizes response hardening for cross-origin browser clients while
 * preserving Slim's default response emission behavior.
 */
class CorsResponseEmitter extends ResponseEmitter
{
    /**
     * Explicit allowlist of origins that may receive credentialed CORS responses.
     *
     * @var list<string>
     */
    private array $allowedOrigins;

    /**
     * @param list<string> $allowedOrigins Explicit allowlist of accepted request origins.
     * @param int $responseChunkSize Maximum body chunk size emitted per iteration.
     */
    public function __construct(array $allowedOrigins = [], int $responseChunkSize = 4096)
    {
        $this->allowedOrigins = array_values(array_unique(array_filter(
            array_map('trim', $allowedOrigins),
            static fn (string $origin): bool => $origin !== ''
        )));

        parent::__construct($responseChunkSize);
    }

    /**
     * {@inheritDoc}
     *
     * Applies CORS/cache headers, clears any active output buffer, and emits the response.
     *
     * @param ResponseInterface $response The response to emit.
     */
    public function emit(ResponseInterface $response): void
    {
        $response = $this->applyHeaders($response);

        if (ob_get_contents()) {
            ob_clean();
        }

        parent::emit($response);
    }

    /**
     * Returns a new response instance with validated CORS and no-cache headers.
     *
     * `Access-Control-Allow-Origin` and credentials headers are only emitted when
     * the current request origin is present in the configured allowlist.
     *
     * @param ResponseInterface $response The response to decorate with headers.
     *
     * @return ResponseInterface The decorated response instance.
     */
    protected function applyHeaders(ResponseInterface $response): ResponseInterface
    {
        $response = $response
            ->withHeader(
                'Access-Control-Allow-Headers',
                'X-Requested-With, Content-Type, Accept, Origin, Authorization'
            )
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            ->withAddedHeader('Cache-Control', 'post-check=0, pre-check=0')
            ->withHeader('Pragma', 'no-cache');

        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if ($origin === null || !in_array($origin, $this->allowedOrigins, true)) {
            return $response;
        }

        return $response
            ->withHeader('Access-Control-Allow-Credentials', 'true')
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withAddedHeader('Vary', 'Origin');
    }
}
