<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPIExamples\Entities;

use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\Traits\AccessTokenTrait;
use T0mmy742\TokenAPI\Entities\Traits\EntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
}
