<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Entities\Traits;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;

use function time;

trait AccessTokenTrait
{
    private DateTimeImmutable $expiryDateTime;
    private string $userIdentifier;
    private Configuration $jwtConfiguration;

    /**
     * Get the token's identifier.
     *
     * @return string
     */
    abstract public function getIdentifier();

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
     * Get the token user's identifier.
     *
     * @return string
     */
    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    /**
     * Set the identifier of the user associated with the token.
     *
     * @param string $identifier
     */
    public function setUserIdentifier(string $identifier): void
    {
        $this->userIdentifier = $identifier;
    }

    /**
     * Set JWT Configuration used to sign access token.
     * @see Configuration
     *
     * @param Configuration $jwtConfiguration
     */
    public function setJwtConfiguration(Configuration $jwtConfiguration): void
    {
        $this->jwtConfiguration = $jwtConfiguration;
    }

    /**
     * Generate a string representation from the access token.
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->convertToJWT()->toString();
    }

    /**
     * Generate a JWT from the access token.
     *
     * @return Token
     */
    private function convertToJWT(): Token
    {
        return $this->jwtConfiguration
            ->builder()
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable('@' . time()))
            ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . time()))
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getUserIdentifier())
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }
}
