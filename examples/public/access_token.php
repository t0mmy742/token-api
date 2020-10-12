<?php

declare(strict_types=1);

use Defuse\Crypto\Key as CryptoKey;
use DI\Container;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use t0mmy742\TokenAPI\AuthorizationServer;
use t0mmy742\TokenAPI\Exception\TokenApiException;
use t0mmy742\TokenAPI\TokenGeneration\TokenGeneration;
use t0mmy742\TokenAPIExamples\Repositories\AccessTokenRepository;
use t0mmy742\TokenAPIExamples\Repositories\RefreshTokenRepository;
use t0mmy742\TokenAPIExamples\Repositories\UserRepository;

include __DIR__ . '/../vendor/autoload.php';

$container = new Container();

$container->set(AuthorizationServer::class, function () {
    return new AuthorizationServer(new TokenGeneration(
        new AccessTokenRepository(),
        new RefreshTokenRepository(),
        new UserRepository(),
        new DateInterval('PT1H'),
        new DateInterval('P1M'),
        Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../private.key'),
            new Key('file://' . __DIR__ . '/../public.key')
        ),
        CryptoKey::loadFromAsciiSafeString('def000001bffc7df14056517020ebc56829102ec3411906b08fea9f99e4a2e5593bcb' .
            'cf53b5016849b545ceba1e9f52157913832e6f3f2e89a3e402a66070cff9e2aaa60')
    ));
});

// Instantiate App
AppFactory::setContainer($container);
$app = AppFactory::create();

// Add error middleware
$app->addErrorMiddleware(true, true, true);

// If your request got a 'refresh_token' attribute, then a new access_token and refresh_token are generated
// from this one. Otherwise, you need to provide an 'username' and a 'password' attribute to get a new access_token.
$app->post(
    '/access_token.php/access_token',
    function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
        $authorizationServer = $app->getContainer()->get(AuthorizationServer::class);

        try {
            return $authorizationServer->respondToTokenRequest($request, $response);
        } catch (TokenApiException $e) {
            $responseBody = json_encode(['error' => $e->getMessage()]) ?: 'JSON encoding failed';

            $response = $app->getResponseFactory()->createResponse();
            $response->getBody()->write($responseBody);

            return $response;
        }
    }
);

$app->run();
