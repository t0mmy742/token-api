<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Crypt;

use Defuse\Crypto\Key;
use PHPUnit\Framework\TestCase;
use T0mmy742\TokenAPI\Crypt\Crypt;
use T0mmy742\TokenAPI\Exception\EncryptionException;

class CryptTest extends TestCase
{
    public function testEncryptDecryptWithKey(): void
    {
        $crypt = new Crypt(Key::createNewRandomKey());

        $unencryptedData = 'I\'m testing this library !';

        $encrypted = $crypt->encrypt($unencryptedData);
        $this->assertNotSame($unencryptedData, $encrypted);

        $unencrypted = $crypt->decrypt($encrypted);
        $this->assertSame($unencryptedData, $unencrypted);
    }

    public function testEncryptException(): void
    {
        $crypt = new Crypt(Key::createNewRandomKey());

        $unencryptedData = 'I\'m testing this library !';

        $GLOBALS['crypto_defuse_exception'] = true;

        $this->expectException(EncryptionException::class);
        $crypt->encrypt($unencryptedData);
    }

    public function testDecryptException(): void
    {
        $crypt = new Crypt(Key::createNewRandomKey());

        $unencryptedData = 'I\'m testing this library !';
        $encryptedData = $crypt->encrypt($unencryptedData);
        $crypt = new Crypt(Key::createNewRandomKey());

        $this->expectException(EncryptionException::class);
        $crypt->decrypt($encryptedData);
    }
}
