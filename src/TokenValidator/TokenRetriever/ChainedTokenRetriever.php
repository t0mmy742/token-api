<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator\TokenRetriever;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;

class ChainedTokenRetriever implements TokenRetrieverInterface
{
    /** @var TokenRetrieverInterface[] */
    private array $tokenRetrievers;

    public function __construct(TokenRetrieverInterface ...$tokenRetrievers)
    {
        $this->tokenRetrievers = $tokenRetrievers;
    }

    public static function default(): self
    {
        return new self(new CookiesTokenRetriever(), new BearerAuthorizationHeaderTokenRetriever());
    }

    public function retrieveToken(ServerRequestInterface $request): string
    {
        foreach ($this->tokenRetrievers as $tokenRetriever) {
            try {
                $token = $tokenRetriever->retrieveToken($request);
                if ($token !== '') {
                    return $token;
                }
            } catch (AccessDeniedException $e) {
                continue;
            }
        }

        return '';
    }
}
