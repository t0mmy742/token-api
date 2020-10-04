<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use t0mmy742\TokenAPI\Exception\EncryptionException;

trait CryptTrait
{
    protected Key $encryptionKey;

    /**
     * Encrypt data with encryption key.
     *
     * @param string $unencryptedData
     * @return string
     * @throws EncryptionException
     */
    protected function encrypt(string $unencryptedData): string
    {
        try {
            return Crypto::encrypt($unencryptedData, $this->encryptionKey);
        } catch (EnvironmentIsBrokenException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt data with encryption key.
     *
     * @param string $encryptedData
     * @return string
     * @throws EncryptionException
     */
    protected function decrypt(string $encryptedData): string
    {
        try {
            return Crypto::decrypt($encryptedData, $this->encryptionKey);
        } catch (EnvironmentIsBrokenException | WrongKeyOrModifiedCiphertextException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }
}
