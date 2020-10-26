<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Crypt;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use T0mmy742\TokenAPI\Exception\EncryptionException;

class Crypt implements CryptInterface
{
    private Key $encryptionKey;

    public function __construct(Key $encryptionKey)
    {
        $this->encryptionKey = $encryptionKey;
    }

    public function encrypt(string $unencryptedData): string
    {
        try {
            return Crypto::encrypt($unencryptedData, $this->encryptionKey);
        } catch (EnvironmentIsBrokenException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    public function decrypt(string $encryptedData): string
    {
        try {
            return Crypto::decrypt($encryptedData, $this->encryptionKey);
        } catch (EnvironmentIsBrokenException | WrongKeyOrModifiedCiphertextException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }
}
