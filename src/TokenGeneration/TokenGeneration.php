<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key;
use Exception;
use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\CryptTrait;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\UserEntityInterface;
use t0mmy742\TokenAPI\Exception\EncryptionException;
use t0mmy742\TokenAPI\Exception\InvalidRefreshTokenException;
use t0mmy742\TokenAPI\Exception\InvalidRequestException;
use t0mmy742\TokenAPI\Exception\JsonEncodingException;
use t0mmy742\TokenAPI\Exception\RandomGenerationException;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;

use function bin2hex;
use function json_decode;
use function json_encode;
use function random_bytes;
use function time;

class TokenGeneration implements TokenGenerationInterface
{
    use CryptTrait;

    private const MAX_TOKEN_GENERATION_ATTEMPTS = 5;

    private AccessTokenRepositoryInterface $accessTokenRepository;
    private RefreshTokenRepositoryInterface $refreshTokenRepository;
    private UserRepositoryInterface $userRepository;
    private DateInterval $accessTokenTTL;
    private DateInterval $refreshTokenTTL;
    private Configuration $jwtConfiguration;

    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        UserRepositoryInterface $userRepository,
        DateInterval $accessTokenTTL,
        DateInterval $refreshTokenTTL,
        Configuration $jwtConfiguration,
        Key $encryptionKey
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->userRepository = $userRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->accessTokenTTL = $accessTokenTTL;
        $this->refreshTokenTTL = $refreshTokenTTL;
        $this->jwtConfiguration = $jwtConfiguration;
        $this->encryptionKey = $encryptionKey;
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
        if (!isset($requestParameters['refresh_token'])) {
            $userId = $this->validateUser($request)->getIdentifier();
        } else {
            $oldRefreshToken = $this->validateOldRefreshToken($request);

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
     * @param mixed $userIdentifier
     * @return AccessTokenEntityInterface
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     *
     * @noinspection PhpInconsistentReturnPointsInspection
     */
    private function issueAccessToken(DateInterval $accessTokenTTL, $userIdentifier): AccessTokenEntityInterface
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
        // @phpstan-ignore-next-line
        // @codeCoverageIgnoreStart
    }
    // @codeCoverageIgnoreEnd

    /**
     * Issue a new refresh token for a previous authorized access token.
     *
     * If the generation is successful, a refresh token entity will be returned.
     *
     * @param AccessTokenEntityInterface $accessToken
     * @return RefreshTokenEntityInterface|null
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     *
     * @noinspection PhpInconsistentReturnPointsInspection
     */
    private function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
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
        // @phpstan-ignore-next-line
        // @codeCoverageIgnoreStart
    }
    // @codeCoverageIgnoreEnd

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
    private function generateHttpResponse(
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
     * @param ServerRequestInterface $request
     * @return array
     * @throws InvalidRefreshTokenException
     */
    private function validateOldRefreshToken(ServerRequestInterface $request): array
    {
        $requestParameters = (array) $request->getParsedBody();

        $encryptedRefreshToken = $requestParameters['refresh_token'];

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
