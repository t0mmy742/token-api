<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator\TokenRetriever;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\TokenValidator\TokenRetriever\BearerAuthorizationHeaderTokenRetriever;

use function trim;

class BearerAuthorizationHeaderTokenValidatorTest extends TestCase
{
    public function testGoodHeader(): void
    {
        $token = 'MY_TOKEN';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenResult = (new BearerAuthorizationHeaderTokenRetriever())->retrieveToken($serverRequest);

        $this->assertSame($token, $tokenResult);
    }

    public function testUntrimmedHeader(): void
    {
        $token = ' MY_TOKEN ';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenResult = (new BearerAuthorizationHeaderTokenRetriever())->retrieveToken($serverRequest);

        $this->assertSame(trim($token), $tokenResult);
    }

    public function testNoHeader(): void
    {
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(false);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Missing "Authorization" header');
        (new BearerAuthorizationHeaderTokenRetriever())->retrieveToken($serverRequest);
    }

    public function testErrorPregReplace(): void
    {
        $token = 'MY_TOKEN';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $GLOBALS['preg_replace_null'] = true;

        $tokenResult = (new BearerAuthorizationHeaderTokenRetriever())->retrieveToken($serverRequest);

        $this->assertEquals('', $tokenResult);
    }
}
