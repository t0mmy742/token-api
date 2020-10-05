<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests;

use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;
use t0mmy742\TokenAPI\Tests\Stubs\CryptTraitStub;

class CryptTraitTest extends TestCase
{
    public function testEncryptDecryptWithKey(): void
    {
        $cryptStub = new CryptTraitStub(Key::createNewRandomKey());

        $unencryptedData = 'I\'m testing this library !';

        $encrypted = $cryptStub->doEncrypt($unencryptedData);
        $this->assertNotSame($unencryptedData, $encrypted);

        $unencrypted = $cryptStub->doDecrypt($encrypted);
        $this->assertSame($unencryptedData, $unencrypted);
    }
}
