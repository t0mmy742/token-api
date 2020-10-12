<?php

declare(strict_types=1);

use AdrianSuter\Autoload\Override\Override;
use Composer\Autoload\ClassLoader;
use Defuse\Crypto\Core;
use T0mmy742\TokenAPI\TokenGeneration\TokenGeneration;

/** @var ClassLoader $classLoader */
$classLoader = require __DIR__ . '/../vendor/autoload.php';

Override::apply($classLoader, [
    Core::class => [
        'random_bytes' => function (int $length): string {
            if (isset($GLOBALS['crypto_defuse_exception'])) {
                unset($GLOBALS['crypto_defuse_exception']);
                throw new Exception();
            }

            return random_bytes($length);
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
                throw new Exception();
            }

            return random_bytes($length);
        }
    ]
]);
