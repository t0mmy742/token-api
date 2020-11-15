<?php

declare(strict_types=1);

use DI\Container;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use T0mmy742\TokenAPI\AuthorizationServer;
use T0mmy742\TokenAPI\Crypt\SodiumCrypt;
use T0mmy742\TokenAPI\Middleware\AuthorizationServerMiddleware;
use T0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use T0mmy742\TokenAPI\ResourceServer;
use T0mmy742\TokenAPI\TokenGeneration\TokenGeneration;
use T0mmy742\TokenAPIExamples\Repositories\AccessTokenRepository;
use T0mmy742\TokenAPIExamples\Repositories\RefreshTokenRepository;
use T0mmy742\TokenAPIExamples\Repositories\UserRepository;

include __DIR__ . '/../vendor/autoload.php';

$container = new Container();

$container->set(AuthorizationServer::class, function () {
    return new AuthorizationServer(new TokenGeneration(
        new AccessTokenRepository(),
        new RefreshTokenRepository(),
        new UserRepository(),
        new SodiumCrypt('PATH_TO_KEYFILE_PREVIOUSLY_GENERATED'),
        new DateInterval('PT1H'),
        new DateInterval('P1M'),
        Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../private.key'),
            new Key('file://' . __DIR__ . '/../public.key')
        )
    ));
});

// Instantiate App
AppFactory::setContainer($container);
$app = AppFactory::create();

// Add error middleware
$app->addErrorMiddleware(true, true, true);

// Access token
$app->post('/middleware.php/access_token', function (ServerRequestInterface $request, ResponseInterface $response) {
    // This function should never be called by the framework since middleware already responded
    return $response;
})->add(new AuthorizationServerMiddleware(
    $app->getContainer()->get(AuthorizationServer::class),
    $app->getResponseFactory()
));

// API secured by the middleware
$app->get('/middleware.php/test', function (ServerRequestInterface $request, ResponseInterface $response) {
    $response->getBody()->write(json_encode([
        'access_token_id' => $request->getAttribute('access_token_id'),
        'user_id' => $request->getAttribute('user_id')
    ]));

    return $response;
})->add(new ResourceServerMiddleware($app->getContainer()->get(ResourceServer::class), $app->getResponseFactory()));

$app->run();
