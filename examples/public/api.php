<?php

declare(strict_types=1);

use DI\Container;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use T0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use T0mmy742\TokenAPI\ResourceServer;
use T0mmy742\TokenAPI\TokenValidator\TokenRetriever\BearerAuthorizationHeaderTokenRetriever;
use T0mmy742\TokenAPI\TokenValidator\TokenValidator;
use T0mmy742\TokenAPIExamples\Repositories\AccessTokenRepository;

include __DIR__ . '/../vendor/autoload.php';

$container = new Container();

$container->set(ResourceServer::class, function () {
    return new ResourceServer(new TokenValidator(
        new AccessTokenRepository(),
        Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../private.key'),
            new Key('file://' . __DIR__ . '/../public.key')
        ),
        new BearerAuthorizationHeaderTokenRetriever()
    ));
});

// Instantiate App
AppFactory::setContainer($container);
$app = AppFactory::create();

// Add error middleware
$app->addErrorMiddleware(true, true, true);

// Add the resource server middleware which will validate requests before everything
$app->add(new ResourceServerMiddleware($app->getContainer()->get(ResourceServer::class), $app->getResponseFactory()));

// A route secured by this middleware
$app->get('/api.php/test', function (ServerRequestInterface $request, ResponseInterface $response) {
    $response->getBody()->write(json_encode([
        // This two attributes are available when request successfully passed ResourceServerMiddleware.
        'access_token_id' => $request->getAttribute('access_token_id'),
        'user_id' => $request->getAttribute('user_id')
    ]));

    return $response;
});

$app->run();
