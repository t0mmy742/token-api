<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\ResourceServer;
use T0mmy742\TokenAPI\TokenValidator\TokenValidatorInterface;

class ResourceServerTest extends TestCase
{
    public function testResourceServer(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $tokenValidator = $this->createMock(TokenValidatorInterface::class);
        $tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($serverRequest)
            ->willReturn($serverRequest->withAttribute('test', 'OK'));

        $resourceServer = new ResourceServer($tokenValidator);

        $resultRequest = $resourceServer->validateAuthenticatedRequest($serverRequest);

        $this->assertSame('OK', $resultRequest->getAttribute('test'));
    }
}
