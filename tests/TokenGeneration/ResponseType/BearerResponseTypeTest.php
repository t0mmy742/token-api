<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration\ResponseType;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use T0mmy742\TokenAPI\Exception\JsonEncodingException;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\BearerResponseType;

use function json_decode;
use function strlen;

class BearerResponseTypeTest extends TestCase
{
    public function testCompleteResponse(): void
    {
        $accessToken = 'MY_ACCESS_TOKEN';
        $expirationAccessToken = 100;
        $refreshToken = 'MY_REFRESH_TOKEN';
        $expirationRefreshToken = 2000;

        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);
        $response
            ->expects($this->once())
            ->method('getBody')
            ->willReturn($stream);
        $stream
            ->expects($this->once())
            ->method('write')
            ->with($this->isType('string'))
            ->willReturnCallback(
                function (string $string) use ($accessToken, $expirationAccessToken, $refreshToken): int {
                    $responseData = json_decode($string, true);
                    $this->assertSame('Bearer', $responseData['token_type']);
                    $this->assertSame($expirationAccessToken - 10, $responseData['expires_in']);
                    $this->assertSame($accessToken, $responseData['access_token']);
                    $this->assertSame($refreshToken, $responseData['refresh_token']);

                    return strlen($string);
                }
            );

        $GLOBALS['time_10'] = true;

        (new BearerResponseType())->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            $refreshToken,
            $expirationRefreshToken
        );
    }

    public function testJsonErrorResponseParams(): void
    {
        $response = $this->createMock(ResponseInterface::class);

        $accessToken = 'MY_ACCESS_TOKEN';
        $expirationAccessToken = 100;
        $refreshToken = 'MY_REFRESH_TOKEN';
        $expirationRefreshToken = 2000;

        $GLOBALS['json_encode_false'] = true;

        $this->expectException(JsonEncodingException::class);
        $this->expectExceptionMessage('Error while JSON encoding response parameters');

        (new BearerResponseType())->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            $refreshToken,
            $expirationRefreshToken
        );
    }
}
