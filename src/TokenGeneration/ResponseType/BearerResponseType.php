<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration\ResponseType;

use Psr\Http\Message\ResponseInterface;
use T0mmy742\TokenAPI\Exception\JsonEncodingException;

use function json_encode;
use function time;

class BearerResponseType implements ResponseTypeInterface
{
    public function completeResponse(
        ResponseInterface $response,
        string $accessToken,
        int $expirationAccessToken,
        ?string $refreshToken,
        ?int $expirationRefreshToken
    ): ResponseInterface {
        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expirationAccessToken - time() ,
            'access_token' => $accessToken,
        ];

        if ($refreshToken !== null) {
            $responseParams['refresh_token'] = $refreshToken;
        }

        $responseParams = json_encode($responseParams);

        if ($responseParams === false) {
            throw new JsonEncodingException('Error while JSON encoding response parameters');
        }

        $response->getBody()->write($responseParams);

        return $response;
    }
}
