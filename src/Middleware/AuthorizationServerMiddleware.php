<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\TokenAPI\AuthorizationServer;
use T0mmy742\TokenAPI\Exception\TokenApiException;

use function json_encode;

class AuthorizationServerMiddleware implements MiddlewareInterface
{
    private AuthorizationServer $authorizationServer;
    private ResponseFactoryInterface $responseFactory;

    public function __construct(AuthorizationServer $authorizationServer, ResponseFactoryInterface $responseFactory)
    {
        $this->authorizationServer = $authorizationServer;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            return $this->authorizationServer->respondToTokenRequest($request, $handler->handle($request));
        } catch (TokenApiException $e) {
            $responseBody = json_encode(['error' => $e->getMessage()]);
            if ($responseBody === false) {
                $responseBody = 'JSON encoding failed';
            }

            $response = $this->responseFactory->createResponse();
            $response->getBody()->write($responseBody);

            return $response;
        }
    }
}
