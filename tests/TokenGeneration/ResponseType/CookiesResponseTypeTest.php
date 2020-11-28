<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration\ResponseType;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\CookiesResponseType;

class CookiesResponseTypeTest extends TestCase
{
    public function testCompleteResponse(): void
    {
        $accessToken = 'MY.ACCESS.TOKEN';
        $accessTokenExploded = ['MY', 'ACCESS', 'TOKEN'];
        $expirationAccessToken = 100;
        $refreshToken = 'MY_REFRESH_TOKEN';
        $expirationRefreshToken = 2000;

        $domain = 'localhost';

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->exactly(3))
            ->method('withAddedHeader')
            ->withConsecutive(
                [
                    'Set-Cookie',
                    'access_token-payload=' . $accessTokenExploded[0] . '.' . $accessTokenExploded[1]
                    . '; domain=' . $domain
                    . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
                    . '; HostOnly; SameSite=Lax'
                ],
                [
                    'Set-Cookie',
                    'access_token-signature=' . $accessTokenExploded[2]
                    . '; domain=' . $domain
                    . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
                    . '; HostOnly; HttpOnly; SameSite=Lax'
                ],
                [
                        'Set-Cookie',
                        'refresh_token=' . $refreshToken
                        . '; domain=' . $domain
                        . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationRefreshToken)
                        . '; HostOnly; HttpOnly; SameSite=Lax'
                ]
            )
            ->willReturn($response);

        (new CookiesResponseType('localhost', false))->completeResponse(
            $response,
            $accessToken,
            $expirationAccessToken,
            $refreshToken,
            $expirationRefreshToken
        );
    }
}
