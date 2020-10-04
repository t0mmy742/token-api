<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI;

use DateInterval;
use Defuse\Crypto\Key;
use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\Exception\TokenApiException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use t0mmy742\TokenAPI\TokenGeneration\AccessTokenGeneration;
use t0mmy742\TokenAPI\TokenGeneration\RefreshTokenGeneration;

class AuthorizationServer
{
    private AccessTokenRepositoryInterface $accessTokenRepository;
    private UserRepositoryInterface $userRepository;
    private RefreshTokenRepositoryInterface $refreshTokenRepository;
    private Configuration $jwtConfiguration;
    private Key $encryptionKey;
    private DateInterval $accessTokenTTL;
    private DateInterval $refreshTokenTTL;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param UserRepositoryInterface $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param Configuration $jwtConfiguration
     * @param Key $encryptionKey
     * @param DateInterval $accessTokenTTL
     * @param DateInterval $refreshTokenTTL
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        Configuration $jwtConfiguration,
        Key $encryptionKey,
        DateInterval $accessTokenTTL,
        DateInterval $refreshTokenTTL
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->userRepository = $userRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->jwtConfiguration = $jwtConfiguration;
        $this->encryptionKey = $encryptionKey;
        $this->accessTokenTTL = $accessTokenTTL;
        $this->refreshTokenTTL = $refreshTokenTTL;
    }

    /**
     * Respond to access token request, and return a response if both an access token and a refresh token.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws TokenApiException
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $accessTokenGeneration = new AccessTokenGeneration(
            $this->userRepository,
            $this->refreshTokenRepository,
            $this->accessTokenTTL,
            $this->refreshTokenTTL,
            $this->accessTokenRepository,
            $this->jwtConfiguration,
            $this->encryptionKey
        );

        return $accessTokenGeneration->respondToTokenRequest($request, $response);
    }

    /**
     * Respond to refresh token request, and return a response if both an access token and a refresh token.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws TokenApiException
     */
    public function respondToRefreshTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $refreshTokenGeneration = new RefreshTokenGeneration(
            $this->userRepository,
            $this->refreshTokenRepository,
            $this->accessTokenTTL,
            $this->refreshTokenTTL,
            $this->accessTokenRepository,
            $this->jwtConfiguration,
            $this->encryptionKey
        );

        return $refreshTokenGeneration->respondToTokenRequest($request, $response);
    }
}
