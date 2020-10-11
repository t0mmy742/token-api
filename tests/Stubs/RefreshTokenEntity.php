<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\Stubs;

use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\Traits\EntityTrait;
use t0mmy742\TokenAPI\Entities\Traits\RefreshTokenTrait;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;
}
