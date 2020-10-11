<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\Middleware;

use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use t0mmy742\TokenAPI\AuthorizationServer;
use t0mmy742\TokenAPI\Exception\TokenApiException;
use t0mmy742\TokenAPI\Middleware\AuthorizationServerMiddleware;
use t0mmy742\TokenAPI\Tests\TestCase;

use function json_encode;

class AuthorizationServerMiddlewareTest extends TestCase
{

    public function testReturnToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/access_token');
        $response = (new ResponseFactory())->createResponse();

        $authorizationServerProphecy = $this->prophesize(AuthorizationServer::class);
        $authorizationServerProphecy->respondToTokenRequest($serverRequest, Argument::type(ResponseInterface::class))
            ->willReturn($response)
            ->shouldBeCalledOnce();
        $authorizationServer = $authorizationServerProphecy->reveal();

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, new ResponseFactory());

        $handler = new class ($response) implements RequestHandlerInterface {
            private ResponseInterface $response;

            public function __construct(ResponseInterface $response)
            {
                $this->response = $response;
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->response;
            }
        };

        $responseResult = $authorizationServerMiddleware->process($serverRequest, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($responseResult, $response);
    }

    public function testBadReturnToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/access_token');

        $authorizationServerProphecy = $this->prophesize(AuthorizationServer::class);
        $authorizationServerProphecy->respondToTokenRequest($serverRequest, Argument::type(ResponseInterface::class))
            ->willThrow(new TokenApiException('Invalid token'))
            ->shouldBeCalledOnce();
        $authorizationServer = $authorizationServerProphecy->reveal();

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, new ResponseFactory());

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse();
            }
        };

        $response = $authorizationServerMiddleware->process($serverRequest, $handler);

        $this->assertSame(json_encode(['error' => 'Invalid token']), (string) $response->getBody());
    }
}
