<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\JWT;

use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Token\RegisteredClaims;

use function array_key_exists;

class UnixTimestampDates implements ClaimsFormatter
{
    public function formatClaims(array $claims): array
    {
        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (array_key_exists($claim, $claims)) {
                $claims[$claim] = $claims[$claim]->getTimestamp();
            }
        }

        return $claims;
    }
}
