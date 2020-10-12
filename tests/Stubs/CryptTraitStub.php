<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Stubs;

use Defuse\Crypto\Key;
use T0mmy742\TokenAPI\CryptTrait;

class CryptTraitStub
{
    use CryptTrait;

    public function __construct(Key $encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;
    }

    public function doEncrypt(string $unencryptedData): string
    {
        return $this->encrypt($unencryptedData);
    }

    public function doDecrypt(string $encryptedData): string
    {
        return $this->decrypt($encryptedData);
    }
}
