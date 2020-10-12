<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\TokenApiException;

interface TokenGenerationInterface
{
    /**
     * Respond to token generation request, validating the parameters of the request.
     *
     * If the generation is successful, a response will be returned.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws TokenApiException
     */
    public function respondToTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface;
}
