<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenValidator;

use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\Exception\AccessDeniedException;

use function preg_replace;
use function trim;

class BearerAuthorizationHeaderTokenValidator extends AbstractTokenValidator
{
    /**
     * Retrieve token from the authorization header.
     *
     * @param ServerRequestInterface $request
     * @return string
     * @throws AccessDeniedException
     */
    protected function retrieveToken(ServerRequestInterface $request): string
    {
        if ($request->hasHeader('authorization') === false) {
            throw new AccessDeniedException('Missing "Authorization" header');
        }

        $header = $request->getHeader('Authorization');
        return trim((string) preg_replace('/^(?:\s+)?Bearer\s/', '', $header[0]));
    }
}
