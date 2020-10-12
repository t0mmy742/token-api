<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\ResourceServer;

use function json_encode;

class ResourceServerMiddleware implements MiddlewareInterface
{
    private ResourceServer $resourceServer;
    private ResponseFactoryInterface $responseFactory;

    public function __construct(ResourceServer $resourceServer, ResponseFactoryInterface $responseFactory)
    {
        $this->resourceServer = $resourceServer;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $request = $this->resourceServer->validateAuthenticatedRequest($request);
        } catch (TokenApiException $e) {
            $responseBody = json_encode(['error' => $e->getMessage()]) ?: 'JSON encoding failed';

            $response = $this->responseFactory->createResponse();
            $response->getBody()->write($responseBody);

            return $response;
        }

        return $handler->handle($request);
    }
}
