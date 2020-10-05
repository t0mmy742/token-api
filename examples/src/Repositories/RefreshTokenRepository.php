<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPIExamples\Repositories;

use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPIExamples\Entities\RefreshTokenEntity;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        // Save the refresh token in a database
        // Throw UniqueTokenIdentifierException if token identifier already exists
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        // Revoke the refresh token from the database
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        return false;
    }
}
