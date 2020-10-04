<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Entities;

use DateTimeImmutable;

interface RefreshTokenEntityInterface
{
    /**
     * Get the token's identifier.
     *
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * Set the token's identifier.
     *
     * @param string $identifier
     */
    public function setIdentifier(string $identifier): void;

    /**
     * Get the token's expiry date time.
     *
     * @return DateTimeImmutable
     */
    public function getExpiryDateTime(): DateTimeImmutable;

    /**
     * Set the date time when the token expires.
     *
     * @param DateTimeImmutable $dateTime
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void;

    /**
     * Set the access token that the refresh token was associated with.
     *
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken(): AccessTokenEntityInterface;

    /**
     * Get the access token that the refresh token was originally associated with.
     *
     * @param AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void;
}
