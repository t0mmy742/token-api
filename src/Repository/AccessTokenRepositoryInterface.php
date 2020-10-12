<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Repository;

use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;

interface AccessTokenRepositoryInterface
{
    /**
     * Create a new access token.
     *
     * @param string $userIdentifier
     * @return AccessTokenEntityInterface
     */
    public function getNewToken(string $userIdentifier): AccessTokenEntityInterface;

    /**
     * Persists a new access token to a permanent storage.
     *
     * @param AccessTokenEntityInterface $accessTokenEntity
     * @throws UniqueTokenIdentifierException
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void;

    /**
     * Revoke an access token.
     *
     * @param string $tokenId
     */
    public function revokeAccessToken(string $tokenId): void;

    /**
     * Check if the access token has been revoked.
     *
     * @param string $tokenId
     * @return bool
     */
    public function isAccessTokenRevoked(string $tokenId): bool;
}
