<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\ResourceServer;
use T0mmy742\TokenAPI\TokenValidator\TokenValidatorInterface;

class ResourceServerTest extends TestCase
{
    public function testResourceServer(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $tokenValidator = $this->createMock(TokenValidatorInterface::class);
        $tokenValidator
            ->expects($this->once())
            ->method('validateToken')
            ->with($serverRequest)
            ->willReturn($serverRequest);

        $resourceServer = new ResourceServer($tokenValidator);

        $resultRequest = $resourceServer->validateAuthenticatedRequest($serverRequest);

        $this->assertSame($serverRequest, $resultRequest);
    }
}
