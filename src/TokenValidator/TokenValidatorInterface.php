<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;

interface TokenValidatorInterface
{
    /**
     * Validate the access token and append properties to the request's attributes.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     * @throws AccessDeniedException
     */
    public function validateToken(ServerRequestInterface $request): ServerRequestInterface;
}
