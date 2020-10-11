<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\Stubs;

use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\Traits\AccessTokenTrait;
use t0mmy742\TokenAPI\Entities\Traits\EntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
}
