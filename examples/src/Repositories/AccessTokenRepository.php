<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPIExamples\Repositories;

use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPIExamples\Entities\AccessTokenEntity;

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
