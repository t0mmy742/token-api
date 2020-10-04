<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Entities\Traits;

use DateTimeImmutable;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;

trait RefreshTokenTrait
{
    private AccessTokenEntityInterface $accessToken;
    private DateTimeImmutable $expiryDateTime;

    /**
     * Get the token's expiry date time.
     *
     * @return DateTimeImmutable
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        return $this->expiryDateTime;
    }

    /**
     * Set the date time when the token expires.
     *
     * @param DateTimeImmutable $dateTime
     */
    public function setExpiryDateTime(DateTimeImmutable $dateTime): void
    {
        $this->expiryDateTime = $dateTime;
    }

    /**
     * Set the access token that the refresh token was associated with.
     *
     * @return AccessTokenEntityInterface
     */
    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }

    /**
     * Get the access token that the refresh token was originally associated with.
     *
     * @param AccessTokenEntityInterface $accessToken
     */
    public function setAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        $this->accessToken = $accessToken;
    }
}
