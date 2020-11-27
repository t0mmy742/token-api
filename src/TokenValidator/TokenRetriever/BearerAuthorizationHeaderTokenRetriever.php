<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator\TokenRetriever;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;

use function preg_replace;
use function trim;

class BearerAuthorizationHeaderTokenRetriever implements TokenRetrieverInterface
{
    /**
     * Retrieve token from the authorization header.
     *
     * @param ServerRequestInterface $request
     * @return string
     * @throws AccessDeniedException
     */
    public function retrieveToken(ServerRequestInterface $request): string
    {
        if ($request->hasHeader('Authorization') === false) {
            throw new AccessDeniedException('Missing "Authorization" header');
        }

        $header = $request->getHeader('Authorization');
        return trim((string) preg_replace('/^(?:\s+)?Bearer\s/', '', $header[0]));
    }
}
