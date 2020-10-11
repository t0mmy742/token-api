<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use Exception;
use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ResponseInterface;
use t0mmy742\TokenAPI\CryptTrait;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Exception\EncryptionException;
use t0mmy742\TokenAPI\Exception\JsonEncodingException;
use t0mmy742\TokenAPI\Exception\RandomGenerationException;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;

use function bin2hex;
use function json_encode;
use function random_bytes;
use function time;

abstract class AbstractTokenGeneration implements TokenGenerationInterface
{
    use CryptTrait;

    private const MAX_TOKEN_GENERATION_ATTEMPTS = 5;

    protected AccessTokenRepositoryInterface $accessTokenRepository;
    protected RefreshTokenRepositoryInterface $refreshTokenRepository;
    protected UserRepositoryInterface $userRepository;
    protected DateInterval $accessTokenTTL;
    protected DateInterval $refreshTokenTTL;
    protected Configuration $jwtConfiguration;

    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $accessTokenTTL,
        DateInterval $refreshTokenTTL,
        AccessTokenRepositoryInterface $accessTokenRepository,
        Configuration $jwtConfiguration,
        Key $encryptionKey
    ) {
        $this->userRepository = $userRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->accessTokenTTL = $accessTokenTTL;
        $this->refreshTokenTTL = $refreshTokenTTL;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->jwtConfiguration = $jwtConfiguration;
        $this->encryptionKey = $encryptionKey;
    }

    /**
     * Issue a new access token for an authorized user.
     *
     * If the generation is successful, an access token entity will be returned.
     *
     * @param DateInterval $accessTokenTTL
     * @param mixed $userIdentifier
     * @return AccessTokenEntityInterface
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     */
    protected function issueAccessToken(DateInterval $accessTokenTTL, $userIdentifier): AccessTokenEntityInterface
    {
        $accessToken = $this->accessTokenRepository->getNewToken($userIdentifier);
        $accessToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add($accessTokenTTL));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);

        $tokenGenerationAttempts = 0;

        while ($tokenGenerationAttempts < self::MAX_TOKEN_GENERATION_ATTEMPTS) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (UniqueTokenIdentifierException $e) {
                $tokenGenerationAttempts++;
                if ($tokenGenerationAttempts === self::MAX_TOKEN_GENERATION_ATTEMPTS) {
                    throw $e;
                }
            }
        }
        // Should not throw this exception
        throw new UniqueTokenIdentifierException('Error while generating access token');
    }

    /**
     * Issue a new refresh token for a previous authorized access token.
     *
     * If the generation is successful, a refresh token entity will be returned.
     *
     * @param AccessTokenEntityInterface $accessToken
     * @return RefreshTokenEntityInterface|null
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();

        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        $tokenGenerationAttempts = 0;

        while ($tokenGenerationAttempts < self::MAX_TOKEN_GENERATION_ATTEMPTS) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                return $refreshToken;
            } catch (UniqueTokenIdentifierException $e) {
                $tokenGenerationAttempts++;
                if ($tokenGenerationAttempts === self::MAX_TOKEN_GENERATION_ATTEMPTS) {
                    throw $e;
                }
            }
        }
        // Should not throw this exception
        throw new UniqueTokenIdentifierException('Error while generating refresh token');
    }

    /**
     * Generate a unique identifier for access token.
     *
     * @return string
     * @throws RandomGenerationException
     */
    private function generateUniqueIdentifier()
    {
        try {
            return bin2hex(random_bytes(32));
        } catch (Exception $e) {
            throw new RandomGenerationException('Could not generate a random string', 0, $e);
        }
    }

    /**
     * Generate a JSON-encoded HTTP Response with an access token and a refresh token.
     *
     * @param ResponseInterface $response
     * @param AccessTokenEntityInterface $accessToken
     * @param RefreshTokenEntityInterface|null $refreshToken
     * @return ResponseInterface
     * @throws EncryptionException
     * @throws JsonEncodingException
     */
    protected function generateHttpResponse(
        ResponseInterface $response,
        AccessTokenEntityInterface $accessToken,
        ?RefreshTokenEntityInterface $refreshToken
    ): ResponseInterface {
        $expireDateTime = $accessToken->getExpiryDateTime()->getTimestamp();

        $responseParams = [
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - time() ,
            'access_token' => (string) $accessToken,
        ];

        if ($refreshToken instanceof RefreshTokenEntityInterface) {
            $refreshTokenPayload = json_encode([
                'refresh_token_id' => $refreshToken->getIdentifier(),
                'access_token_id'  => $accessToken->getIdentifier(),
                'user_id'          => $accessToken->getUserIdentifier(),
                'expire_time'      => $refreshToken->getExpiryDateTime()->getTimestamp()
            ]);

            if ($refreshTokenPayload === false) {
                throw new JsonEncodingException('Error while JSON encoding the refresh token payload');
            }

            $responseParams['refresh_token'] = $this->encrypt($refreshTokenPayload);
        }

        $responseParams = json_encode($responseParams);

        if ($responseParams === false) {
            throw new JsonEncodingException('Error while JSON encoding response parameters');
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write($responseParams);

        return $response;
    }
}
