<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPIExamples\Repositories;

use t0mmy742\TokenAPI\Entities\UserEntityInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use t0mmy742\TokenAPIExamples\Entities\UserEntity;

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
