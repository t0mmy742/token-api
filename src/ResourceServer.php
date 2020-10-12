<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\TokenValidator\TokenValidatorInterface;

class ResourceServer
{
    private TokenValidatorInterface $tokenValidator;

    public function __construct(TokenValidatorInterface $tokenValidator)
    {
        $this->tokenValidator = $tokenValidator;
    }

    /**
     * Determine the access token validity.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     * @throws TokenApiException
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request): ServerRequestInterface
    {
        return $this->tokenValidator->validateToken($request);
    }
}
