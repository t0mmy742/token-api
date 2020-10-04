<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Entities;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;

interface AccessTokenEntityInterface
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
     * Get the token user's identifier.
     *
     * @return string
     */
    public function getUserIdentifier(): string;

    /**
     * Set the identifier of the user associated with the token.
     *
     * @param string $identifier
     */
    public function setUserIdentifier(string $identifier): void;

    /**
     * Set JWT Configuration used to sign access token.
     *
     * @param Configuration $jwtConfiguration
     */
    public function setJwtConfiguration(Configuration $jwtConfiguration): void;

    /**
     * Generate a string representation of the access token.
     *
     * @return string
     */
    public function __toString(): string;
}
