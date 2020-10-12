<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests;

use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\AuthorizationServer;
use T0mmy742\TokenAPI\TokenGeneration\TokenGenerationInterface;

class AuthorizationServerTest extends TestCase
{
    public function testAuthorizationServer(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token');
        $response = (new ResponseFactory())->createResponse();

        $tokenGenerationProphecy = $this->prophesize(TokenGenerationInterface::class);
        $tokenGenerationProphecy->respondToTokenRequest($serverRequest, $response)->willReturn($response);

        $authorizationServer = new AuthorizationServer($tokenGenerationProphecy->reveal());

        $responseResult = $authorizationServer->respondToTokenRequest($serverRequest, $response);

        $this->assertSame($response, $responseResult);
    }
}
