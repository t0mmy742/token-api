<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests;

use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\ResourceServer;
use T0mmy742\TokenAPI\TokenValidator\TokenValidatorInterface;

class ResourceServerTest extends TestCase
{
    public function testResourceServer(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $tokenValidatorProphecy = $this->prophesize(TokenValidatorInterface::class);
        $tokenValidatorProphecy->validateToken($serverRequest)->willReturn($serverRequest->withAttribute('test', 'OK'));

        $resourceServer = new ResourceServer($tokenValidatorProphecy->reveal());

        $resultRequest = $resourceServer->validateAuthenticatedRequest($serverRequest);

        $this->assertSame('OK', $resultRequest->getAttribute('test'));
    }
}
