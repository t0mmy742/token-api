<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Entities;

interface UserEntityInterface
{
    /**
     * Return the user's identifier.
     *
     * @return string
     */
    public function getIdentifier(): string;
}
