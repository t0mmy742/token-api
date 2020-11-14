<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Crypt;

use T0mmy742\TokenAPI\Exception\EncryptionException;

use function base64_decode;
use function base64_encode;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function is_readable;
use function mb_strlen;
use function mb_substr;
use function random_bytes;
use function sodium_bin2hex;
use function sodium_crypto_secretbox;
use function sodium_crypto_secretbox_keygen;
use function sodium_crypto_secretbox_open;
use function sodium_hex2bin;
use function sodium_memzero;

use const SODIUM_CRYPTO_SECRETBOX_KEYBYTES;
use const SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

class SodiumCrypt implements CryptInterface
{
    private string $keyPath;

    public function __construct(string $keyPath)
    {
        $this->keyPath = $keyPath;
    }

    public function encrypt(string $unencryptedData): string
    {
        $key = $this->loadKey();

        if (mb_strlen($key, '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new EncryptionException('Key is not the correct size (must be 32 bytes).');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $ciphertext = base64_encode($nonce . sodium_crypto_secretbox($unencryptedData, $nonce, $key));

        sodium_memzero($unencryptedData);
        sodium_memzero($key);

        return $ciphertext;
    }

    public function decrypt(string $encryptedData): string
    {
        $key = $this->loadKey();

        $decoded = base64_decode($encryptedData, true);
        if ($decoded === false) {
            throw new EncryptionException('Bad decoding');
        }
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        if ($plaintext === false) {
            throw new EncryptionException('Bad ciphertext');
        }

        sodium_memzero($ciphertext);
        sodium_memzero($nonce);
        sodium_memzero($key);

        return $plaintext;
    }

    /**
     * @param bool $overwrite
     * @throws EncryptionException
     */
    public function generateSaveKey(bool $overwrite = false): bool
    {
        if (file_exists($this->keyPath) && $overwrite === false) {
            throw new EncryptionException('Key file already exists. Use `overwrite` parameter to create a new file');
        }

        $key = sodium_bin2hex(sodium_crypto_secretbox_keygen());
        file_put_contents($this->keyPath, $key);
        sodium_memzero($key);

        return true;
    }

    /**
     * @return string
     * @throws EncryptionException
     */
    private function loadKey(): string
    {
        if (!is_readable($this->keyPath)) {
            throw new EncryptionException('Cannot read key file');
        }

        $keyFileData = file_get_contents($this->keyPath);
        if ($keyFileData === false) {
            throw new EncryptionException('Cannot load key from file');
        }

        $key = sodium_hex2bin($keyFileData);
        sodium_memzero($keyFileData);

        return $key;
    }
}
