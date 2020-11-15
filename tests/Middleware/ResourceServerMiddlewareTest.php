<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use T0mmy742\TokenAPI\ResourceServer;

use function json_encode;

class ResourceServerMiddlewareTest extends TestCase
{
    public function testValidToken(): void
    {
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
            ->willReturnArgument(0);

        $resourceServerMiddleware = new ResourceServerMiddleware(
            $resourceServer,
            $this->createStub(ResponseFactoryInterface::class)
        );

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler
            ->expects($this->once())
            ->method('handle')
            ->with($serverRequest)
            ->willReturn($response);

        $responseResult = $resourceServerMiddleware->process($serverRequest, $handler);

        $this->assertSame($responseResult, $response);
    }

    public function testInvalidToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
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

        $resourceServerMiddleware = new ResourceServerMiddleware($resourceServer, $responseFactory);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $resourceServerMiddleware->process($serverRequest, $handler);
    }

    public function testBadJsonEncoding(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
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

        $resourceServerMiddleware = new ResourceServerMiddleware($resourceServer, $responseFactory);

        $handler = $this->createStub(RequestHandlerInterface::class);

        $GLOBALS['json_encode_false'] = true;

        $resourceServerMiddleware->process($serverRequest, $handler);
    }
}
