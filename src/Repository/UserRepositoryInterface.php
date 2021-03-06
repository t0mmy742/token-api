<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Repository;

use T0mmy742\TokenAPI\Entities\UserEntityInterface;

interface UserRepositoryInterface
{
    /**
     * Get a user entity from his credentials.
     *
     * @param string $username
     * @param string $password
     * @return UserEntityInterface|null
     */
    public function getUserEntityByUserCredentials(string $username, string $password): ?UserEntityInterface;
}
