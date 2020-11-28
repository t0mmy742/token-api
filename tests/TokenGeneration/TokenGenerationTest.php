<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use T0mmy742\TokenAPI\Crypt\CryptInterface;
use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use T0mmy742\TokenAPI\Exception\EncryptionException;
use T0mmy742\TokenAPI\Exception\InvalidRefreshTokenException;
use T0mmy742\TokenAPI\Exception\InvalidRequestException;
use T0mmy742\TokenAPI\Exception\JsonEncodingException;
use T0mmy742\TokenAPI\Exception\RandomGenerationException;
use T0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use T0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use T0mmy742\TokenAPI\Tests\Stubs\AccessTokenEntity;
use T0mmy742\TokenAPI\Tests\Stubs\RefreshTokenEntity;
use T0mmy742\TokenAPI\Tests\Stubs\UserEntity;
use T0mmy742\TokenAPI\TokenGeneration\ResponseType\ResponseTypeInterface;
use T0mmy742\TokenAPI\TokenGeneration\TokenGeneration;

use function json_encode;
use function strlen;
use function time;

class TokenGenerationTest extends TestCase
{
    private TokenGeneration $tokenGeneration;
    /** @var AccessTokenRepositoryInterface&MockObject */
    private AccessTokenRepositoryInterface $accessTokenRepository;
    /** @var RefreshTokenRepositoryInterface&MockObject */
    private RefreshTokenRepositoryInterface $refreshTokenRepository;
    /** @var UserRepositoryInterface&MockObject */
    private UserRepositoryInterface $userRepository;
    /** @var ResponseTypeInterface&MockObject */
    private ResponseTypeInterface $responseType;
    /** @var CryptInterface&MockObject */
    private CryptInterface $crypt;
    private Configuration $jwtConfiguration;

    protected function setUp(): void
    {
        $this->accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->userRepository = $this->createMock(UserRepositoryInterface::class);
        $this->responseType = $this->createMock(ResponseTypeInterface::class);
        $this->crypt = $this->createMock(CryptInterface::class);
        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            Key\LocalFileReference::file(__DIR__ . '/../Stubs/private.key'),
            Key\LocalFileReference::file(__DIR__ . '/../Stubs/public.key')
        );

        $this->tokenGeneration = new TokenGeneration(
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->userRepository,
            $this->responseType,
            $this->crypt,
            new DateInterval('PT1H'),
            new DateInterval('P1M'),
            $this->jwtConfiguration
        );
    }

    public function testGoodIssueAccessToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueAccessToken');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepository
            ->expects($this->once())
            ->method('getNewToken')
            ->with('1')
            ->willReturn($accessToken);

        $this->accessTokenRepository
            ->expects($this->once())
            ->method("persistNewAccessToken")
            ->with($this->isInstanceOf(AccessTokenEntityInterface::class));

        $accessTokenResult = $method->invoke($this->tokenGeneration, new DateInterval('PT1H'), '1');

        $this->assertSame($accessToken, $accessTokenResult);
        $this->assertSame(64, strlen($accessTokenResult->getIdentifier()));
    }

    public function testIssueAccessTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueAccessToken');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepository
            ->expects($this->once())
            ->method('getNewToken')
            ->with('1')
            ->willReturn($accessToken);

        $this->accessTokenRepository
            ->expects($this->exactly(5))
            ->method("persistNewAccessToken")
            ->willThrowException(new UniqueTokenIdentifierException());

        $this->expectException(UniqueTokenIdentifierException::class);
        $method->invoke($this->tokenGeneration, new DateInterval('PT1H'), '1');
    }

    public function testGoodIssueRefreshToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $refreshToken = new RefreshTokenEntity();
        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('getNewRefreshToken')
            ->willReturn($refreshToken);

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method("persistNewRefreshToken")
            ->with($this->isInstanceOf(RefreshTokenEntityInterface::class));

        $accessToken = new AccessTokenEntity();

        $refreshTokenResult = $method->invoke($this->tokenGeneration, $accessToken);

        $this->assertSame($refreshToken, $refreshTokenResult);
        $this->assertSame($accessToken, $refreshTokenResult->getAccessToken());
    }

    public function testIssueRefreshTokenNullToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method("getNewRefreshToken")
            ->willReturn(null);

        $refreshTokenResult = $method->invoke($this->tokenGeneration, new AccessTokenEntity());

        $this->assertNull($refreshTokenResult);
    }

    public function testIssueRefreshTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $refreshToken = new RefreshTokenEntity();
        $this->refreshTokenRepository
            ->expects($this->once())
            ->method("getNewRefreshToken")
            ->willReturn($refreshToken);

        $this->refreshTokenRepository
            ->expects($this->exactly(5))
            ->method('persistNewRefreshToken')
            ->with($this->isInstanceOf(RefreshTokenEntityInterface::class))
            ->willThrowException(new UniqueTokenIdentifierException());

        $this->expectException(UniqueTokenIdentifierException::class);
        $method->invoke($this->tokenGeneration, new AccessTokenEntity());
    }

    public function testGenerateUniqueIdentifierException(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateUniqueIdentifier');
        $method->setAccessible(true);

        $GLOBALS['random_bytes_exception'] = true;

        $this->expectException(RandomGenerationException::class);
        $this->expectExceptionMessage('Could not generate a random string');
        $this->expectExceptionCode(0);
        $method->invoke($this->tokenGeneration);
    }

    public function testGoodGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessTokenExpiryDateTime = (new DateTimeImmutable())->add(new DateInterval('PT1H'));
        $accessToken->setExpiryDateTime($accessTokenExpiryDateTime);
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $refreshToken = new RefreshTokenEntity();
        $refreshTokenExpiryDateTime = (new DateTimeImmutable())->add(new DateInterval('P1M'));
        $refreshToken->setExpiryDateTime($refreshTokenExpiryDateTime);
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setIdentifier('REFRESH_TOKEN_ID');

        $this->assertSame($accessToken, $refreshToken->getAccessToken());

        $this->crypt
            ->expects($this->once())
            ->method('encrypt')
            ->with($this->isType('string'))
            ->willReturnArgument(0);

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(200)
            ->willReturn($response);
        $response
            ->expects($this->exactly(3))
            ->method('withHeader')
            ->withConsecutive(
                ['pragma', 'no-cache'],
                ['cache-control', 'no-store'],
                ['content-type', 'application/json; charset=UTF-8']
            )
            ->willReturn($response);

        $method->invoke($this->tokenGeneration, $response, $accessToken, $refreshToken);
    }

    public function testGoodGenerateHttpResponseWithoutRefreshToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessTokenExpiryDateTime = (new DateTimeImmutable())->add(new DateInterval('PT1H'));
        $accessToken->setExpiryDateTime($accessTokenExpiryDateTime);
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(200)
            ->willReturn($response);
        $response
            ->expects($this->exactly(3))
            ->method('withHeader')
            ->withConsecutive(
                ['pragma', 'no-cache'],
                ['cache-control', 'no-store'],
                ['content-type', 'application/json; charset=UTF-8']
            )
            ->willReturn($response);

        $this->responseType
            ->expects($this->once())
            ->method('completeResponse')
            ->with($response, $this->isType('string'), $this->isType('int'), null, null)
            ->willReturnArgument(0);

        $method->invoke($this->tokenGeneration, $response, $accessToken, null);
    }

    public function testJsonErrorRefreshTokenPayloadGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('P1M')));
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setIdentifier('REFRESH_TOKEN_ID');

        $response = $this->createStub(ResponseInterface::class);

        $GLOBALS['json_encode_false'] = true;

        $this->expectException(JsonEncodingException::class);
        $this->expectExceptionMessage('Error while JSON encoding the refresh token payload');
        $method->invoke($this->tokenGeneration, $response, $accessToken, $refreshToken);
    }

    public function testValidRespondToTokenRequest(): void
    {
        // PSR-7 ServerRequestInterface::getParsedBody can return null|array|object.
        $parsedBody = (object) [
            'username' => 'admin',
            'password' => 'pass'
        ];

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->exactly(2))
            ->method('getParsedBody')
            ->willReturn($parsedBody);

        $this->userRepository
            ->expects($this->once())
            ->method('getUserEntityByUserCredentials')
            ->with('admin', 'pass')
            ->willReturn(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepository
            ->expects($this->once())
            ->method('getNewToken')
            ->with('1')
            ->willReturn($accessToken);

        $this->accessTokenRepository
            ->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($this->isInstanceOf(AccessTokenEntityInterface::class));

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('getNewRefreshToken')
            ->willReturn(new RefreshTokenEntity());

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('persistNewRefreshToken')
            ->with($this->isInstanceOf(RefreshTokenEntityInterface::class));

        $this->crypt
            ->expects($this->once())
            ->method('encrypt')
            ->with($this->isType('string'))
            ->willReturn('ENCRYPTED_REFRESH_TOKEN');

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(200)
            ->willReturn($response);
        $response
            ->expects($this->exactly(3))
            ->method('withHeader')
            ->withConsecutive(
                ['pragma', 'no-cache'],
                ['cache-control', 'no-store'],
                ['content-type', 'application/json; charset=UTF-8']
            )
            ->willReturn($response);

        $this->responseType
            ->expects($this->once())
            ->method('completeResponse')
            ->with(
                $response,
                $this->isType('string'),
                $this->isType('int'),
                $this->isType('string'),
                $this->isType('int')
            )
            ->willReturnArgument(0);

        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testNoUsername(): void
    {
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->exactly(2))
            ->method('getParsedBody')
            ->willReturn(null);

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('username');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testNoPassword(): void
    {
        $parsedBody = [
            'username' => 'admin'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->exactly(2))
            ->method('getParsedBody')
            ->willReturn($parsedBody);

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('password');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testBadIdentification(): void
    {
        $parsedBody = [
            'username' => 'admin',
            'password' => 'pass'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->exactly(2))
            ->method('getParsedBody')
            ->willReturn($parsedBody);

        $this->userRepository
            ->expects($this->once())
            ->method('getUserEntityByUserCredentials')
            ->with('admin', 'pass')
            ->willReturn(null);

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid identification');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testValidRespondToTokenRequestWithRefreshToken(): void
    {
        $refreshTokenPayload = json_encode([
            'refresh_token_id' => 'REFRESH_TOKEN_ID',
            'access_token_id'  => 'ACCESS_TOKEN_ID',
            'user_id'          => 'USER_ID',
            'expire_time'      => time() + 3600
        ]);
        // PSR-7 ServerRequestInterface::getParsedBody can return null|array|object.
        $parsedBody = (object) [
            'refresh_token' => 'REFRESH_TOKEN'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn($parsedBody);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn([]);

        $this->crypt
            ->expects($this->once())
            ->method('decrypt')
            ->with('REFRESH_TOKEN')
            ->willReturn($refreshTokenPayload);

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('isRefreshTokenRevoked')
            ->with('REFRESH_TOKEN_ID')
            ->willReturn(false);

        $this->accessTokenRepository
            ->expects($this->once())
            ->method('revokeAccessToken')
            ->with('ACCESS_TOKEN_ID');

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('revokeRefreshToken')
            ->with('REFRESH_TOKEN_ID');

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $this->accessTokenRepository
            ->expects($this->once())
            ->method('getNewToken')
            ->with('USER_ID')
            ->willReturn($accessToken);

        $this->accessTokenRepository
            ->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($this->isInstanceOf(AccessTokenEntityInterface::class));

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('getNewRefreshToken')
            ->willReturn(new RefreshTokenEntity());

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('persistNewRefreshToken')
            ->with($this->isInstanceOf(RefreshTokenEntityInterface::class));

        $this->crypt
            ->expects($this->once())
            ->method('encrypt')
            ->with($this->isType('string'))
            ->willReturn('ENCRYPTED_REFRESH_TOKEN');

        $response = $this->createMock(ResponseInterface::class);
        $response
            ->expects($this->once())
            ->method('withStatus')
            ->with(200)
            ->willReturn($response);
        $response
            ->expects($this->exactly(3))
            ->method('withHeader')
            ->withConsecutive(
                ['pragma', 'no-cache'],
                ['cache-control', 'no-store'],
                ['content-type', 'application/json; charset=UTF-8']
            )
            ->willReturn($response);

        $this->responseType
            ->expects($this->once())
            ->method('completeResponse')
            ->with(
                $response,
                $this->isType('string'),
                $this->isType('int'),
                $this->isType('string'),
                $this->isType('int')
            )
            ->willReturnArgument(0);

        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testBadEncryptionRefreshToken(): void
    {
        $cookies = [
            'refresh_token' => 'BAD_REFRESH_TOKEN'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([]);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn($cookies);

        $this->crypt
            ->expects($this->once())
            ->method('decrypt')
            ->with('BAD_REFRESH_TOKEN')
            ->willThrowException(new EncryptionException());

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Cannot decrypt the refresh token');
        $this->expectExceptionCode(0);
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testExpiredRefreshToken(): void
    {
        $refreshTokenPayload = json_encode([
            'refresh_token_id' => 'REFRESH_TOKEN_ID',
            'access_token_id'  => 'ACCESS_TOKEN_ID',
            'user_id'          => 'USER_ID',
            'expire_time'      => time()
        ]);
        $cookies = [
            '__Secure-refresh_token' => 'REFRESH_TOKEN'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([]);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn($cookies);

        $this->crypt
            ->expects($this->once())
            ->method('decrypt')
            ->with('REFRESH_TOKEN')
            ->willReturn($refreshTokenPayload);

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Token has expired');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }

    public function testRevokedRefreshToken(): void
    {
        $refreshTokenPayload = json_encode([
            'refresh_token_id' => 'REFRESH_TOKEN_ID',
            'access_token_id'  => 'ACCESS_TOKEN_ID',
            'user_id'          => 'USER_ID',
            'expire_time'      => time() + 3600
        ]);

        $parsedBody = [
            'refresh_token' => 'REFRESH_TOKEN'
        ];
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn($parsedBody);
        $serverRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn([]);

        $this->crypt
            ->expects($this->once())
            ->method('decrypt')
            ->with('REFRESH_TOKEN')
            ->willReturn($refreshTokenPayload);

        $this->refreshTokenRepository
            ->expects($this->once())
            ->method('isRefreshTokenRevoked')
            ->with('REFRESH_TOKEN_ID')
            ->willReturn(true);

        $response = $this->createStub(ResponseInterface::class);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Token has been revoked');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, $response);
    }
}
