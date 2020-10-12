<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPIExamples\Repositories;

use T0mmy742\TokenAPI\Entities\UserEntityInterface;
use T0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use T0mmy742\TokenAPIExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials(string $username, string $password): ?UserEntityInterface
    {
        if ($username === 'admin' && $password === 'pass') {
            return new UserEntity();
        }

        return null;
    }
}
