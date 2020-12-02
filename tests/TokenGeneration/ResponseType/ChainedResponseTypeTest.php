<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration\ResponseType;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\ChainedResponseType;

class ChainedResponseTypeTest extends TestCase
{
    public function testNoResponseType(): void
    {
        $response = $this->createStub(ResponseInterface::class);

        $accessToken = 'MY_ACCESS_TOKEN';
        $expirationAccessToken = 100;
        $refreshToken = 'MY_REFRESH_TOKEN';
        $expirationRefreshToken = 2000;

        $newResponse = (new ChainedResponseType())->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            $refreshToken,
            $expirationRefreshToken
        );

        $this->assertSame($response, $newResponse);
    }

    public function testDefautResponseTypeIsSecure(): void
    {
        $chainedResponseType = ChainedResponseType::default();

        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);
        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with($this->isType('string'));
        $response
            ->expects($this->exactly(2))
            ->method('withAddedHeader')
            ->willReturnCallback(
                function (string $name, $value) use ($response): ResponseInterface {
                    $this->assertStringContainsString('Secure;', $value);

                    return $response;
                }
            );

        $accessToken = 'MY.ACCESS.TOKEN';
        $expirationAccessToken = 100;

        $newResponse = $chainedResponseType->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            null,
            null
        );

        $this->assertSame($response, $newResponse);
    }
}
