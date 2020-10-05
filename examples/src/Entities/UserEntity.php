<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPIExamples\Entities;

use t0mmy742\TokenAPI\Entities\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    public function getIdentifier(): string
    {
        return '1';
    }
}
