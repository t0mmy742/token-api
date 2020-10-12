<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Stubs;

use T0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\Traits\EntityTrait;
use T0mmy742\TokenAPI\Entities\Traits\RefreshTokenTrait;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;
}
