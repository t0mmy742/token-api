<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPIExamples\Entities;

use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\Traits\EntityTrait;
use t0mmy742\TokenAPI\Entities\Traits\RefreshTokenTrait;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;
}
