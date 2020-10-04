<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI;

use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\Exception\AccessDeniedException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\TokenValidator\TokenValidator;

class ResourceServer
{
    private AccessTokenRepositoryInterface $accessTokenRepository;
    private Configuration $jwtConfiguration;

    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, Configuration $jwtConfiguration)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->jwtConfiguration = $jwtConfiguration;
    }

    /**
     * Determine the access token validity.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     * @throws AccessDeniedException
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request): ServerRequestInterface
    {
        return (new TokenValidator($this->accessTokenRepository, $this->jwtConfiguration))->validateToken($request);
    }
}
