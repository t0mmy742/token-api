<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Entities\Traits;

trait EntityTrait
{
    private string $identifier;

    /**
     * Get the token's identifier.
     *
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * Set the token's identifier.
     *
     * @param string $identifier
     */
    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }
}
