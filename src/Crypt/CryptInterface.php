<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Crypt;

use T0mmy742\TokenAPI\Exception\EncryptionException;

interface CryptInterface
{
    /**
     * Encrypt data with encryption key.
     *
     * @param string $unencryptedData
     * @return string
     * @throws EncryptionException
     */
    public function encrypt(string $unencryptedData): string;

    /**
     * Decrypt data with encryption key.
     *
     * @param string $encryptedData
     * @return string
     * @throws EncryptionException
     */
    public function decrypt(string $encryptedData): string;
}
