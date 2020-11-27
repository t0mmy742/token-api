<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator\TokenRetriever;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;

class CookiesTokenRetriever implements TokenRetrieverInterface
{
    /**
     * Retrieve token from two cookies : access_token-payload and access_token-signature.
     *
     * @param ServerRequestInterface $request
     * @return string
     * @throws AccessDeniedException
     */
    public function retrieveToken(ServerRequestInterface $request): string
    {
        $cookies = $request->getCookieParams();
        if (!(isset($cookies['access_token-payload']) && isset($cookies['access_token-signature']))) {
            throw new AccessDeniedException('Missing "access_token-payload" and/or "access_token-signature" cookies');
        }

        return $cookies['access_token-payload'] . '.' . $cookies['access_token-signature'];
    }
}
