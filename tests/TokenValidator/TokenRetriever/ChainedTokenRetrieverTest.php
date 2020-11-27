<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator\TokenRetriever;

use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\TokenValidator\TokenRetriever\ChainedTokenRetriever;
use PHPUnit\Framework\TestCase;
use T0mmy742\TokenAPI\TokenValidator\TokenRetriever\TokenRetrieverInterface;

class ChainedTokenRetrieverTest extends TestCase
{
    public function testNoTokenRetriever(): void
    {
        $chainedTokenRetriever = new ChainedTokenRetriever();

        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $chainedTokenRetriever->retrieveToken($serverRequest);

        $this->assertSame('', $token);
    }

    public function testDefautTokenRetriever(): void
    {
        $chainedTokenRetriever = ChainedTokenRetriever::default();

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(false);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn([]);

        $token = $chainedTokenRetriever->retrieveToken($serverRequest);

        $this->assertSame('', $token);
    }

    public function testRetrieveTokenReturnTokenAfterFirstFailedString(): void
    {
        $tokenRetriever1 = $this->createMock(TokenRetrieverInterface::class);
        $tokenRetriever1
            ->expects($this->once())
            ->method('retrieveToken')
            ->willThrowException(new AccessDeniedException());

        $tokenRetriever2 = $this->createMock(TokenRetrieverInterface::class);
        $tokenRetriever2
            ->expects($this->once())
            ->method('retrieveToken')
            ->with($this->isInstanceOf(ServerRequestInterface::class))
            ->willReturn('MY_TOKEN');

        $chainedTokenRetriever = new ChainedTokenRetriever($tokenRetriever1, $tokenRetriever2);

        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $chainedTokenRetriever->retrieveToken($serverRequest);

        $this->assertSame('MY_TOKEN', $token);
    }
}
