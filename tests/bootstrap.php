<?php

declare(strict_types=1);

use AdrianSuter\Autoload\Override\Override;
use Composer\Autoload\ClassLoader;
use Defuse\Crypto\Core;
use t0mmy742\StreamWrapper\StreamWrapper;
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
    Core::class => [
        'random_bytes' => function (int $length): string {
            if (isset($GLOBALS['crypto_defuse_exception'])) {
                unset($GLOBALS['crypto_defuse_exception']);
                throw new RuntimeException();
            }

            return random_bytes($length);
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
