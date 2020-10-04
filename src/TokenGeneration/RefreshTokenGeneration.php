<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenGeneration;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\Exception\EncryptionException;
use t0mmy742\TokenAPI\Exception\InvalidRefreshTokenException;
use t0mmy742\TokenAPI\Exception\InvalidRequestException;
use t0mmy742\TokenAPI\Exception\JsonEncodingException;
use t0mmy742\TokenAPI\Exception\RandomGenerationException;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;

use function json_decode;
use function time;

class RefreshTokenGeneration extends AbstractTokenGeneration
{
    /**
     * Respond to token generation request, validating the parameters of the request.
     *
     * If the generation is successful, a response will be returned.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws EncryptionException
     * @throws InvalidRefreshTokenException
     * @throws InvalidRequestException
     * @throws JsonEncodingException
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     */
    public function respondToTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $oldRefreshToken = $this->validateOldRefreshToken($request);

        $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
        $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);

        $accessToken = $this->issueAccessToken($this->accessTokenTTL, $oldRefreshToken['user_id']);

        $refreshToken = $this->issueRefreshToken($accessToken);

        return $this->generateHttpResponse($response, $accessToken, $refreshToken);
    }

    /**
     * Validate refresh token contained in request parameters.
     *
     * If the validation is successful, an array will be returned with refresh token information.
     *
     * @param ServerRequestInterface $request
     * @return array
     * @throws InvalidRefreshTokenException
     * @throws InvalidRequestException
     */
    private function validateOldRefreshToken(ServerRequestInterface $request): array
    {
        $requestParameters = (array) $request->getParsedBody();

        $encryptedRefreshToken = $requestParameters['refresh_token'] ?? null;
        if ($encryptedRefreshToken === null) {
            throw new InvalidRequestException('refresh_token');
        }

        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (EncryptionException $e) {
            throw new InvalidRefreshTokenException('Cannot decrypt the refresh token', 0, $e);
        }

        $refreshTokenData = json_decode($refreshToken, true);

        if ($refreshTokenData['expire_time'] < time()) {
            throw new InvalidRefreshTokenException('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw new InvalidRefreshTokenException('Token has been revoked');
        }

        return $refreshTokenData;
    }
}
