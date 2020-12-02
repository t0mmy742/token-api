<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration\ResponseType;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\CookiesResponseType;

use function gmdate;

class CookiesResponseTypeTest extends TestCase
{
    public function testDefaultCookieIsSecure(): void
    {
        $accessToken = 'MY.ACCESS.TOKEN';
        $accessTokenExploded = ['MY', 'ACCESS', 'TOKEN'];
        $expirationAccessToken = 100;
        $refreshToken = 'MY_REFRESH_TOKEN';
        $expirationRefreshToken = 2000;

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->exactly(3))
            ->method('withAddedHeader')
            ->withConsecutive(
                [
                    'Set-Cookie',
                    '__Secure-access_token-payload=' . $accessTokenExploded[0] . '.' . $accessTokenExploded[1]
                    . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
                    . '; Secure; HostOnly; SameSite=Lax'
                ],
                [
                    'Set-Cookie',
                    '__Secure-access_token-signature=' . $accessTokenExploded[2]
                    . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
                    . '; Secure; HostOnly; HttpOnly; SameSite=Lax'
                ],
                [
                    'Set-Cookie',
                    '__Secure-refresh_token=' . $refreshToken
                    . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationRefreshToken)
                    . '; Secure; HostOnly; HttpOnly; SameSite=Lax'
                ]
            )
            ->willReturn($response);

        (new CookiesResponseType(null))->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            $refreshToken,
            $expirationRefreshToken
        );
    }
}
