<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration\ResponseType;

use Psr\Http\Message\ResponseInterface;
use T0mmy742\TokenAPI\Exception\JsonEncodingException;

interface ResponseTypeInterface
{
    /**
     * @param ResponseInterface $response
     * @param string $accessToken
     * @param int $expirationAccessToken
     * @param string|null $refreshToken
     * @param int|null $expirationRefreshToken
     * @return ResponseInterface
     * @throws JsonEncodingException
     */
    public function completeResponse(
        ResponseInterface $response,
        string $accessToken,
        int $expirationAccessToken,
        ?string $refreshToken,
        ?int $expirationRefreshToken
    ): ResponseInterface;
}
