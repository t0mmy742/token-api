<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator\TokenRetriever;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;

interface TokenRetrieverInterface
{
    /**
     * Retrieve token.
     *
     * @param ServerRequestInterface $request
     * @return string
     * @throws AccessDeniedException
     */
    public function retrieveToken(ServerRequestInterface $request): string;
}
