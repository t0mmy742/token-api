<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Crypt;

use PHPUnit\Framework\TestCase;
use T0mmy742\TokenAPI\Crypt\SodiumCrypt;
use T0mmy742\TokenAPI\Exception\EncryptionException;

class SodiumCryptTest extends TestCase
{
    public function testGenerateSaveKey(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['file_exists'] = true;
        $GLOBALS['file_put_contents'] = true;

        $this->assertTrue($crypt->generateSaveKey(true));
    }

    public function testGenerateSaveKeyAlreadyExists(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['file_exists'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Key file already exists. Use `overwrite` parameter to create a new file');
        $this->expectExceptionCode(0);

        $crypt->generateSaveKey();
    }

    public function testGenerateSaveKeyAlreadyExistsButCanOverwrite(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['file_exists'] = true;
        $GLOBALS['file_put_contents'] = true;

        $this->assertTrue($crypt->generateSaveKey(true));
    }

    public function testGenerateSaveKeyBin2HexFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['file_exists'] = false;
        $GLOBALS['sodium_bin2hex_failed'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while converting binary key to hexadecimal');
        $this->expectExceptionCode(0);

        $crypt->generateSaveKey();
    }

    public function testGenerateSaveKeyMemzeroFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['file_exists'] = false;
        $GLOBALS['file_put_contents'] = true;
        $GLOBALS['sodium_memzero_failed'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while cleaning memory');
        $this->expectExceptionCode(0);

        $crypt->generateSaveKey();
    }

    public function testLoadKeyNotReadable(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = false;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cannot read key file');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testLoadKeyNotLoadable(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = false;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cannot load key from file');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testLoadKeyHex2BinFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_hex2bin_failed'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while converting hexadecimal key to binary');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testLoadKeyMemzeroFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_memzero_failed'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while cleaning memory');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testEncryptKeyIncorrectSize(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['mb_strlen'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Key is not the correct size (must be 32 bytes).');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testEncryptNoRandomBytes(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['random_bytes_exception'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cannot generate random bytes');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testEncryptEncryptionFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_crypto_secretbox_failed'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while encrypting text');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testEncryptMemzeroFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_memzero_failed_2'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while cleaning memory');
        $this->expectExceptionCode(0);

        $crypt->encrypt('Test data to encrypt.');
    }

    public function testEncrypt(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;

        $unencrypted = 'Test data to encrypt.';
        $encrypted = $crypt->encrypt($unencrypted);

        $this->assertNotSame($unencrypted, $encrypted);
    }

    public function testDecryptBadDecoding(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['base64_decode_false'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Bad decoding');
        $this->expectExceptionCode(0);

        $encrypted = 'egaOnyu+OKqmo4rt/+cCsK+ctBVp6FiaC9AswffnRmLniI9m6xD3+jtQqXt89/0OTZBVsqu6ZVGEkrc91A==';
        $crypt->decrypt($encrypted);
    }

    public function testDecryptFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_crypto_secretbox_open_exception'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while decrypting text');
        $this->expectExceptionCode(0);

        $encrypted = 'egaOnyu+OKqmo4rt/+cCsK+ctBVp6FiaC9AswffnRmLniI9m6xD3+jtQqXt89/0OTZBVsqu6ZVGEkrc91A==';
        $crypt->decrypt($encrypted);
    }

    public function testDecryptBadCiphertext(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_crypto_secretbox_open_false'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Bad ciphertext');
        $this->expectExceptionCode(0);

        $encrypted = 'egaOnyu+OKqmo4rt/+cCsK+ctBVp6FiaC9AswffnRmLniI9m6xD3+jtQqXt89/0OTZBVsqu6ZVGEkrc91A==';
        $crypt->decrypt($encrypted);
    }

    public function testDecryptMemzeroFailed(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;
        $GLOBALS['sodium_memzero_failed_2'] = true;

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Error while cleaning memory');
        $this->expectExceptionCode(0);

        $encrypted = 'egaOnyu+OKqmo4rt/+cCsK+ctBVp6FiaC9AswffnRmLniI9m6xD3+jtQqXt89/0OTZBVsqu6ZVGEkrc91A==';
        $crypt->decrypt($encrypted);
    }

    public function testDecrypt(): void
    {
        $crypt = new SodiumCrypt(__DIR__ . '/../../build/testKey');

        $GLOBALS['is_readable'] = true;
        $GLOBALS['file_get_contents'] = true;

        $encrypted = 'egaOnyu+OKqmo4rt/+cCsK+ctBVp6FiaC9AswffnRmLniI9m6xD3+jtQqXt89/0OTZBVsqu6ZVGEkrc91A==';
        $unencrypted = $crypt->decrypt($encrypted);

        $this->assertSame('Test data to encrypt.', $unencrypted);
    }
}
