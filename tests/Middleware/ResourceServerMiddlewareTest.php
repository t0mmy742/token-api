<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\Exception\TokenApiException;
use T0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use T0mmy742\TokenAPI\ResourceServer;

use function json_encode;

class ResourceServerMiddlewareTest extends TestCase
{
    public function testValidToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
            ->willReturn(
                $serverRequest
                    ->withAttribute('access_token_id', 'token_id')
                    ->withAttribute('user_id', '1')
            );

        $resourceServerMiddleware = new ResourceServerMiddleware($resourceServer, new ResponseFactory());

        $handler = new class extends TestCase implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->assertSame('1', $request->getAttribute('user_id'));
                return (new ResponseFactory())->createResponse();
            }
        };

        $response = $resourceServerMiddleware->process($serverRequest, $handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testInvalidToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/badTest');

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
            ->willThrowException(new TokenApiException('Invalid token'));

        $resourceServerMiddleware = new ResourceServerMiddleware($resourceServer, new ResponseFactory());

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse();
            }
        };

        $response = $resourceServerMiddleware->process($serverRequest, $handler);

        $this->assertSame(json_encode(['error' => 'Invalid token']), (string) $response->getBody());
    }

    public function testBadJsonEncoding(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/badTest');

        $resourceServer = $this->createMock(ResourceServer::class);
        $resourceServer
            ->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($serverRequest)
            ->willThrowException(new TokenApiException('Invalid token'));

        $resourceServerMiddleware = new ResourceServerMiddleware($resourceServer, new ResponseFactory());

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new ResponseFactory())->createResponse();
            }
        };

        $GLOBALS['json_encode_false'] = true;

        $response = $resourceServerMiddleware->process($serverRequest, $handler);

        $this->assertSame('JSON encoding failed', (string) $response->getBody());
    }
}
