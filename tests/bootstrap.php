<?php

declare(strict_types=1);

use AdrianSuter\Autoload\Override\Override;
use Composer\Autoload\ClassLoader;
use t0mmy742\StreamWrapper\StreamWrapper;
use T0mmy742\TokenAPI\Crypt\SodiumCrypt;
use T0mmy742\TokenAPI\Middleware\AuthorizationServerMiddleware;
use T0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use T0mmy742\TokenAPI\TokenGeneration\TokenGeneration;
use T0mmy742\TokenAPI\TokenValidator\BearerAuthorizationHeaderTokenValidator;

/** @var ClassLoader $classLoader */
$classLoader = require __DIR__ . '/../vendor/autoload.php';

Override::apply($classLoader, [
    AuthorizationServerMiddleware::class => [
        'json_encode' => function ($value) {
            if (isset($GLOBALS['json_encode_false'])) {
                unset($GLOBALS['json_encode_false']);
                return false;
            }

            return json_encode($value);
        }
    ],
    BearerAuthorizationHeaderTokenValidator::class => [
        'preg_replace' => function ($pattern, $replacement, $subject, $limit = -1, &$count = null) {
            if (isset($GLOBALS['preg_replace_null'])) {
                unset($GLOBALS['preg_replace_null']);
                return null;
            }

            return preg_replace($pattern, $replacement, $subject, $limit, $count);
        }
    ],
    ResourceServerMiddleware::class => [
        'json_encode' => function ($value) {
            if (isset($GLOBALS['json_encode_false'])) {
                unset($GLOBALS['json_encode_false']);
                return false;
            }

            return json_encode($value);
        }
    ],
    SodiumCrypt::class => [
        'base64_decode' => function (string $data) {
            if (isset($GLOBALS['base64_decode_false'])) {
                unset($GLOBALS['base64_decode_false']);
                return false;
            }

            return base64_decode($data, true);
        },
        'file_exists' => function (string $filename): bool {
            if (isset($GLOBALS['file_exists'])) {
                $return = $GLOBALS['file_exists'];
                unset($GLOBALS['file_exists']);
                return $return;
            }

            return file_exists($filename);
        },
        'file_get_contents' => function (string $filename) {
            if (isset($GLOBALS['file_get_contents'])) {
                $return = $GLOBALS['file_get_contents'];
                unset($GLOBALS['file_get_contents']);
                if ($return === true) {
                    return '6a0ec376e2519f20eeef2a32de12587050ba09e214b4055842dba4f9f1b991b6';
                } elseif ($return === false) {
                    return false;
                } else {
                    return $return;
                }
            }

            return file_get_contents($filename);
        },
        'file_put_contents' => function ($filename, $data) {
            if (isset($GLOBALS['file_put_contents'])) {
                unset($GLOBALS['file_put_contents']);
                return 0;
            }

            return file_put_contents($filename, $data);
        },
        'is_readable' => function (string $filename): bool {
            if (isset($GLOBALS['is_readable'])) {
                $return = $GLOBALS['is_readable'];
                unset($GLOBALS['is_readable']);
                return $return;
            }

            return is_readable($filename);
        },
        'mb_strlen' => function (string $str, $encoding = null) {
            if (isset($GLOBALS['mb_strlen'])) {
                unset($GLOBALS['mb_strlen']);
                return 0;
            }

            return mb_strlen($str, $encoding);
        },
        'random_bytes' => function (int $length): string {
            if (isset($GLOBALS['random_bytes_exception'])) {
                unset($GLOBALS['random_bytes_exception']);
                throw new RuntimeException();
            }

            return random_bytes($length);
        },
        'sodium_bin2hex' => function (string $binary): string {
            if (isset($GLOBALS['sodium_bin2hex_failed'])) {
                unset($GLOBALS['sodium_bin2hex_failed']);
                throw new SodiumException();
            }

            return sodium_bin2hex($binary);
        },
        'sodium_crypto_secretbox' => function (string $plaintext, string $nonce, string $key): string {
            if (isset($GLOBALS['sodium_crypto_secretbox_failed'])) {
                unset($GLOBALS['sodium_crypto_secretbox_failed']);
                throw new SodiumException();
            }

            return sodium_crypto_secretbox($plaintext, $nonce, $key);
        },
        'sodium_crypto_secretbox_open' => function (string $ciphertext, string $nonce, string $key) {
            if (isset($GLOBALS['sodium_crypto_secretbox_open_false'])) {
                unset($GLOBALS['sodium_crypto_secretbox_open_false']);
                return false;
            } elseif (isset($GLOBALS['sodium_crypto_secretbox_open_exception'])) {
                unset($GLOBALS['sodium_crypto_secretbox_open_exception']);
                throw new SodiumException();
            }

            return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
        },
        'sodium_hex2bin' => function (string $hex): string {
            if (isset($GLOBALS['sodium_hex2bin_failed'])) {
                unset($GLOBALS['sodium_hex2bin_failed']);
                throw new SodiumException();
            }

            return sodium_hex2bin($hex);
        },
        'sodium_memzero' => function (string $buf): void {
            if (isset($GLOBALS['sodium_memzero_failed'])) {
                unset($GLOBALS['sodium_memzero_failed']);
                throw new SodiumException();
            } elseif (isset($GLOBALS['sodium_memzero_failed_2'])) {
                if (
                    isset($GLOBALS['sodium_memzero_failed_2_counter'])
                    && ++$GLOBALS['sodium_memzero_failed_2_counter'] === 2
                ) {
                    unset($GLOBALS['sodium_memzero_failed_2']);
                    unset($GLOBALS['sodium_memzero_failed_2_counter']);
                    throw new SodiumException();
                } else {
                    $GLOBALS['sodium_memzero_failed_2_counter'] = 1;
                }
            }

            sodium_memzero($buf);
        }
    ],
    TokenGeneration::class => [
        'json_encode' => function ($value) {
            if (isset($GLOBALS['json_encode_false'])) {
                unset($GLOBALS['json_encode_false']);
                return false;
            }

            return json_encode($value);
        },
        'random_bytes' => function (int $length): string {
            if (isset($GLOBALS['random_bytes_exception'])) {
                unset($GLOBALS['random_bytes_exception']);
                throw new RuntimeException();
            }

            return random_bytes($length);
        },
        'time' => function (): int {
            if (isset($GLOBALS['time_10'])) {
                unset($GLOBALS['time_10']);
                return 10;
            }

            return time();
        }
    ]
]);

StreamWrapper::enable();
