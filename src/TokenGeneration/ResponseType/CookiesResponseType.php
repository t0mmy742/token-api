<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration\ResponseType;

use Psr\Http\Message\ResponseInterface;

class CookiesResponseType implements ResponseTypeInterface
{
    private string $domain;
    private bool $secure;

    public function __construct(string $domain, bool $secure)
    {
        $this->domain = $domain;
        $this->secure = $secure;
    }

    public function completeResponse(
        ResponseInterface $response,
        string $accessToken,
        int $expirationAccessToken,
        ?string $refreshToken,
        ?int $expirationRefreshToken
    ): ResponseInterface {
        $cookies = $this->createCookies($accessToken, $expirationAccessToken, $refreshToken, $expirationRefreshToken);

        foreach ($cookies as $cookie) {
            $response = $response->withAddedHeader('Set-Cookie', $cookie);
        }

        return $response;
    }

    /**
     * @param string $accessToken
     * @param int $expirationAccessToken
     * @param string|null $refreshToken
     * @param int|null $expirationRefreshToken
     * @return string[]
     */
    private function createCookies(
        string $accessToken,
        int $expirationAccessToken,
        ?string $refreshToken,
        ?int $expirationRefreshToken
    ): array {
        $accessToken = explode('.', $accessToken);

        $cookies = [
            ($this->secure ? '__Secure-' : '') . 'access_token-payload=' . $accessToken[0] . '.' . $accessToken[1]
            . '; domain=' . $this->domain
            . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
            . '; ' . ($this->secure ? 'secure; ' : '')
            . 'HostOnly; SameSite=Lax',
            ($this->secure ? '__Secure-' : '') . 'access_token-signature=' . $accessToken[2]
            . '; domain=' . $this->domain
            . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationAccessToken)
            . '; ' . ($this->secure ? 'secure; ' : '')
            . 'HostOnly; HttpOnly; SameSite=Lax'
        ];

        if ($refreshToken !== null) {
            $cookies[] = ($this->secure ? '__Secure-' : '') . 'refresh_token=' . $refreshToken
                . '; domain=' . $this->domain
                . '; path=/; expires=' . gmdate('D, d-M-Y H:i:s e', $expirationRefreshToken)
                . '; ' . ($this->secure ? 'secure; ' : '')
                . 'HostOnly; HttpOnly; SameSite=Lax';
        }

        return $cookies;
    }

    /**
     * @return string[]
     */
    /*
    private function deleteCookies(): array
    {
        return [
            ($this->secure ? '__Secure-' : '') . 'access_token-payload='
            . '; domain=' . $this->domain
            . '; path=/; expires=1'
            . ';' . ($this->secure ? 'secure; ' : '')
            . 'HostOnly; SameSite=Lax',
            ($this->secure ? '__Secure-' : '') . 'access_token-signature='
            . '; domain=' . $this->domain
            . '; path=/; expires=1'
            . '; ' . ($this->secure ? 'secure; ' : '')
            . 'HostOnly; HttpOnly; SameSite=Lax',
            ($this->secure ? '__Secure-' : '') . 'refresh_token='
            . '; domain=' . $this->domain
            . '; path=/; expires=1'
            . '; ' . ($this->secure ? 'secure; ' : '')
            . 'HostOnly; HttpOnly; SameSite=Lax'
        ];
    }
    */
}
