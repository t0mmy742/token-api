<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Crypt\CryptInterface;
use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\UserEntityInterface;
use T0mmy742\TokenAPI\Exception\EncryptionException;
use T0mmy742\TokenAPI\Exception\InvalidRefreshTokenException;
use T0mmy742\TokenAPI\Exception\InvalidRequestException;
use T0mmy742\TokenAPI\Exception\JsonEncodingException;
use T0mmy742\TokenAPI\Exception\RandomGenerationException;
use T0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use T0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\ResponseTypeInterface;

use function bin2hex;
use function json_decode;
use function json_encode;
use function random_bytes;
use function time;

class TokenGeneration implements TokenGenerationInterface
{
    private const MAX_TOKEN_GENERATION_ATTEMPTS = 5;

    private AccessTokenRepositoryInterface $accessTokenRepository;
    private RefreshTokenRepositoryInterface $refreshTokenRepository;
    private UserRepositoryInterface $userRepository;
    private ResponseTypeInterface $responseType;
    private CryptInterface $crypt;
    private DateInterval $accessTokenTTL;
    private DateInterval $refreshTokenTTL;
    private Configuration $jwtConfiguration;

    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        UserRepositoryInterface $userRepository,
        ResponseTypeInterface $responseType,
        CryptInterface $crypt,
        DateInterval $accessTokenTTL,
        DateInterval $refreshTokenTTL,
        Configuration $jwtConfiguration
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->userRepository = $userRepository;
        $this->responseType = $responseType;
        $this->crypt = $crypt;
        $this->accessTokenTTL = $accessTokenTTL;
        $this->refreshTokenTTL = $refreshTokenTTL;
        $this->jwtConfiguration = $jwtConfiguration;
    }

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
        $requestParameters = (array) $request->getParsedBody();
        $cookies = $request->getCookieParams();
        if (isset($requestParameters['refresh_token'])) {
            $refreshToken = $requestParameters['refresh_token'];
        } elseif (isset($cookies['__Secure-refresh_token'])) {
            $refreshToken = $cookies['__Secure-refresh_token'];
        } elseif (isset($cookies['refresh_token'])) {
            $refreshToken = $cookies['refresh_token'];
        }
        if (!isset($refreshToken)) {
            $userId = $this->validateUser($request)->getIdentifier();
        } else {
            $oldRefreshToken = $this->validateOldRefreshToken($refreshToken);

            $this->accessTokenRepository->revokeAccessToken($oldRefreshToken['access_token_id']);
            $this->refreshTokenRepository->revokeRefreshToken($oldRefreshToken['refresh_token_id']);

            $userId = $oldRefreshToken['user_id'];
        }
        $accessToken = $this->issueAccessToken($this->accessTokenTTL, $userId);
        $refreshToken = $this->issueRefreshToken($accessToken);

        return $this->generateHttpResponse($response, $accessToken, $refreshToken);
    }

    /**
     * Issue a new access token for an authorized user.
     *
     * If the generation is successful, an access token entity will be returned.
     *
     * @param DateInterval $accessTokenTTL
     * @param string $userIdentifier
     * @return AccessTokenEntityInterface
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     */
    private function issueAccessToken(DateInterval $accessTokenTTL, string $userIdentifier): AccessTokenEntityInterface
    {
        $accessToken = $this->accessTokenRepository->getNewToken($userIdentifier);
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);

        $tokenGenerationAttempts = 0;

        while ($tokenGenerationAttempts++ < self::MAX_TOKEN_GENERATION_ATTEMPTS) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (UniqueTokenIdentifierException $e) {
                $exception = $e;
            }
        }
        /** @noinspection PhpUndefinedVariableInspection */
        throw $exception;
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
    private function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();

        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new DateTimeImmutable())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        $tokenGenerationAttempts = 0;

        while ($tokenGenerationAttempts++ < self::MAX_TOKEN_GENERATION_ATTEMPTS) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                return $refreshToken;
            } catch (UniqueTokenIdentifierException $e) {
                $exception = $e;
            }
        }
        /** @noinspection PhpUndefinedVariableInspection */
        throw $exception;
    }

    /**
     * Generate a unique identifier for access token.
     *
     * @return string
     * @throws RandomGenerationException
     */
    private function generateUniqueIdentifier(): string
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
    private function generateHttpResponse(
        ResponseInterface $response,
        AccessTokenEntityInterface $accessToken,
        ?RefreshTokenEntityInterface $refreshToken
    ): ResponseInterface {
        $expireDateTime = $accessToken->getExpiryDateTime()->getTimestamp();

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

            $encryptedRefreshToken = $this->crypt->encrypt($refreshTokenPayload);
        }

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response = $this->responseType->completeResponse(
            $response,
            (string) $accessToken,
            $expireDateTime,
            $encryptedRefreshToken ?? null,
            $refreshToken?->getExpiryDateTime()?->getTimestamp()
        );

        return $response;
    }

    /**
     * Validate request parameters used for user identification.
     *
     * If the validation is successful, a UserEntity will be returned.
     *
     * @param ServerRequestInterface $request
     * @return UserEntityInterface
     * @throws InvalidRequestException
     */
    private function validateUser(ServerRequestInterface $request): UserEntityInterface
    {
        $requestParameters = (array) $request->getParsedBody();

        $username = $requestParameters['username'] ?? null;
        if ($username === null) {
            throw new InvalidRequestException('username');
        }

        $password = $requestParameters['password'] ?? null;
        if ($password === null) {
            throw new InvalidRequestException('password');
        }

        $user = $this->userRepository->getUserEntityByUserCredentials($username, $password);
        if ($user instanceof UserEntityInterface === false) {
            throw new InvalidRequestException('Invalid identification');
        }

        return $user;
    }

    /**
     * Validate refresh token contained in request parameters.
     *
     * If the validation is successful, an array will be returned with refresh token information.
     *
     * @param string $encryptedRefreshToken
     * @return array<string, string>
     * @throws InvalidRefreshTokenException
     */
    private function validateOldRefreshToken(string $encryptedRefreshToken): array
    {
        try {
            $refreshToken = $this->crypt->decrypt($encryptedRefreshToken);
        } catch (EncryptionException $e) {
            throw new InvalidRefreshTokenException('Cannot decrypt the refresh token', 0, $e);
        }

        $refreshTokenData = json_decode($refreshToken, true);

        if ($refreshTokenData['expire_time'] <= time()) {
            throw new InvalidRefreshTokenException('Token has expired');
        }

        if ($this->refreshTokenRepository->isRefreshTokenRevoked($refreshTokenData['refresh_token_id']) === true) {
            throw new InvalidRefreshTokenException('Token has been revoked');
        }

        return $refreshTokenData;
    }
}
