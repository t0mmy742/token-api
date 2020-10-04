<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Repository;

use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;

interface RefreshTokenRepositoryInterface
{
    /**
     * Create a new refresh token.
     *
     * @return RefreshTokenEntityInterface|null
     */
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface;

    /**
     * Persists a new access token to a permanent storage.
     *
     * @param RefreshTokenEntityInterface $refreshTokenEntity
     * @throws UniqueTokenIdentifierException
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void;

    /**
     * Revoke the refresh token.
     *
     * @param string $tokenId
     */
    public function revokeRefreshToken(string $tokenId): void;

    /**
     * Check if the refresh token has been revoked.
     *
     * @param string $tokenId
     * @return bool
     */
    public function isRefreshTokenRevoked(string $tokenId): bool;
}
