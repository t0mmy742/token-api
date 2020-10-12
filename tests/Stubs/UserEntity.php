<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Stubs;

use T0mmy742\TokenAPI\Entities\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    public function getIdentifier(): string
    {
        return '1';
    }
}
