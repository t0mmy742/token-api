<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenValidator;

use Psr\Http\Message\ServerRequestInterface;

interface TokenValidatorInterface
{
    /**
     * Validate the access token in the authorization header and append properties to the request's attributes.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function validateToken(ServerRequestInterface $request): ServerRequestInterface;
}
