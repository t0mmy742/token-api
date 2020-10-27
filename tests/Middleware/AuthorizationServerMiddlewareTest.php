<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\AuthorizationServer;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\Middleware\AuthorizationServerMiddleware;

use function json_encode;

class AuthorizationServerMiddlewareTest extends TestCase
{
    public function testReturnToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/access_token');
        $response = (new ResponseFactory())->createResponse();

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willReturn($response);

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

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willThrowException(new TokenApiException('Invalid token'));

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

    public function testBadJsonEncoding(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/access_token');

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willThrowException(new TokenApiException('Invalid token'));

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, new ResponseFactory());

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse();
            }
        };

        $GLOBALS['json_encode_false'] = true;

        $response = $authorizationServerMiddleware->process($serverRequest, $handler);

        $this->assertSame('JSON encoding failed', (string) $response->getBody());
    }
}
