<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPIExamples\Repositories;

use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPIExamples\Entities\AccessTokenEntity;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function getNewToken(string $userIdentifier): AccessTokenEntityInterface
    {
        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier($userIdentifier);

        return $accessToken;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        // Save the access token in a database
        // Throw UniqueTokenIdentifierException if token identifier already exists
    }

    public function revokeAccessToken(string $tokenId): void
    {
        // Revoke the access token from the database
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return false;
    }
}
