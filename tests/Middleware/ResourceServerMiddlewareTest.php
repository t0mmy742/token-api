<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use t0mmy742\TokenAPI\Exception\TokenApiException;
use t0mmy742\TokenAPI\Middleware\ResourceServerMiddleware;
use t0mmy742\TokenAPI\ResourceServer;

use function json_encode;

class ResourceServerMiddlewareTest extends TestCase
{
    use ProphecyTrait;

    public function testValidToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $resourceServerProphecy = $this->prophesize(ResourceServer::class);
        $resourceServerProphecy->validateAuthenticatedRequest($serverRequest)
            ->willReturn(
                $serverRequest
                    ->withAttribute('access_token_id', 'token_id')
                    ->withAttribute('user_id', '1')
            )
            ->shouldBeCalledOnce();
        $resourceServer = $resourceServerProphecy->reveal();

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

        $resourceServerProphecy = $this->prophesize(ResourceServer::class);
        $resourceServerProphecy->validateAuthenticatedRequest($serverRequest)
            ->willThrow(new TokenApiException('Invalid token'))
            ->shouldBeCalledOnce();
        $resourceServer = $resourceServerProphecy->reveal();

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
}
