<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\TokenAPI\AuthorizationServer;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\Middleware\AuthorizationServerMiddleware;

use function json_encode;

class AuthorizationServerMiddlewareTest extends TestCase
{
    public function testReturnToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $responseFactory = $this->createStub(ResponseFactoryInterface::class);

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willReturn($response);

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, $responseFactory);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->expects($this->once())
            ->method('handle')
            ->with($serverRequest)
            ->willReturn($response);

        $responseResult = $authorizationServerMiddleware->process($serverRequest, $handler);

        $this->assertSame($responseResult, $response);
    }

    public function testBadReturnToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willThrowException(new TokenApiException('Invalid token'));

        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory
            ->expects($this->once())
            ->method('createResponse')
            ->willReturn($response);
        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with(json_encode(['error' => 'Invalid token']));

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, $responseFactory);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $authorizationServerMiddleware->process($serverRequest, $handler);
    }

    public function testBadJsonEncoding(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $authorizationServer = $this->createMock(AuthorizationServer::class);
        $authorizationServer
            ->expects($this->once())
            ->method('respondToTokenRequest')
            ->with($serverRequest, $this->isInstanceOf(ResponseInterface::class))
            ->willThrowException(new TokenApiException('Invalid token'));

        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);
        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory
            ->expects($this->once())
            ->method('createResponse')
            ->willReturn($response);
        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with('JSON encoding failed');

        $authorizationServerMiddleware = new AuthorizationServerMiddleware($authorizationServer, $responseFactory);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $GLOBALS['json_encode_false'] = true;

        $authorizationServerMiddleware->process($serverRequest, $handler);
    }
}
