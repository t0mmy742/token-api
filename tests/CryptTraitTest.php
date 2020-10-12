<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests;

use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;
use T0mmy742\TokenAPI\Exception\EncryptionException;
use T0mmy742\TokenAPI\Tests\Stubs\CryptTraitStub;

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

    public function testEncryptException(): void
    {
        $cryptStub = new CryptTraitStub(Key::createNewRandomKey());

        $unencryptedData = 'I\'m testing this library !';

        $GLOBALS['crypto_defuse_exception'] = true;

        $this->expectException(EncryptionException::class);
        $cryptStub->doEncrypt($unencryptedData);
    }
}
