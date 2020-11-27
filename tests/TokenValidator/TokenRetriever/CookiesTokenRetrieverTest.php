<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator\TokenRetriever;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\TokenValidator\TokenRetriever\CookiesTokenRetriever;

class CookiesTokenRetrieverTest extends TestCase
{
    public function testWithCookies(): void
    {
        $tokenPayload = 'MY_TOKEN-payload';
        $tokenSignature = 'MY_TOKEN-signature';
        $cookies = [
            'access_token-payload' => $tokenPayload,
            'access_token-signature' => $tokenSignature
        ];

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn($cookies);

        $tokenResult = (new CookiesTokenRetriever())->retrieveToken($serverRequest);

        $this->assertSame($tokenPayload . '.' . $tokenSignature, $tokenResult);
    }

    public function testMissingCookie(): void
    {
        $tokenPayload = 'MY_TOKEN-payload';
        $cookies = [
            'access_token-payload' => $tokenPayload
        ];

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn($cookies);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Missing "access_token-payload" and/or "access_token-signature" cookies');
        (new CookiesTokenRetriever())->retrieveToken($serverRequest);
    }
}
