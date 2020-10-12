<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\TokenGeneration\TokenGenerationInterface;

class AuthorizationServer
{
    private TokenGenerationInterface $tokenGeneration;

    /**
     * @param TokenGenerationInterface $tokenGeneration
     */
    public function __construct(TokenGenerationInterface $tokenGeneration)
    {
        $this->tokenGeneration = $tokenGeneration;
    }

    /**
     * Respond to token request, and return a response with both an access token and a refresh token.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws TokenApiException
     */
    public function respondToTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        return $this->tokenGeneration->respondToTokenRequest($request, $response);
    }
}
