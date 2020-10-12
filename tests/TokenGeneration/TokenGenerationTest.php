<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key as KeyCrypt;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ResponseInterface;
use ReflectionClass;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use T0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
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
use T0mmy742\TokenAPI\Tests\TestCase;
use T0mmy742\TokenAPI\TokenGeneration\TokenGeneration;

use function json_encode;
use function time;

class TokenGenerationTest extends TestCase
{
    private TokenGeneration $tokenGeneration;
    private ObjectProphecy $accessTokenRepositoryProphecy;
    private ObjectProphecy $refreshTokenRepositoryProphecy;
    private ObjectProphecy $userRepositoryProphecy;
    private Configuration $jwtConfiguration;
    private KeyCrypt $keyCrypt;

    protected function setUp(): void
    {
        $this->accessTokenRepositoryProphecy = $this->prophesize(AccessTokenRepositoryInterface::class);
        $this->refreshTokenRepositoryProphecy = $this->prophesize(RefreshTokenRepositoryInterface::class);
        $this->userRepositoryProphecy = $this->prophesize(UserRepositoryInterface::class);
        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../Stubs/private.key'),
            new Key('file://' . __DIR__ . '/../Stubs/public.key')
        );
        $this->keyCrypt = KeyCrypt::createNewRandomKey();

        $this->tokenGeneration = new TokenGeneration(
            $this->accessTokenRepositoryProphecy->reveal(),
            $this->refreshTokenRepositoryProphecy->reveal(),
            $this->userRepositoryProphecy->reveal(),
            new DateInterval('PT1H'),
            new DateInterval('P1M'),
            $this->jwtConfiguration,
            $this->keyCrypt
        );
    }

    public function testGoodIssueAccessToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueAccessToken');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepositoryProphecy
            ->getNewToken('1')
            ->shouldBeCalledOnce()
            ->willReturn($accessToken);

        $this->accessTokenRepositoryProphecy
            ->persistNewAccessToken(Argument::type(AccessTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $accessTokenResult = $method->invoke($this->tokenGeneration, new DateInterval('PT1H'), '1');

        $this->assertSame($accessToken, $accessTokenResult);
    }

    public function testIssueAccessTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueAccessToken');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepositoryProphecy
            ->getNewToken('1')
            ->shouldBeCalledOnce()
            ->willReturn($accessToken);

        $this->accessTokenRepositoryProphecy
            ->persistNewAccessToken(Argument::type(AccessTokenEntityInterface::class))
            ->shouldBeCalledTimes(5)
            ->willThrow(UniqueTokenIdentifierException::class);

        $this->expectException(UniqueTokenIdentifierException::class);
        $method->invoke($this->tokenGeneration, new DateInterval('PT1H'), '1');
    }

    public function testGoodIssueRefreshToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $refreshToken = new RefreshTokenEntity();
        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn($refreshToken);

        $this->refreshTokenRepositoryProphecy
            ->persistNewRefreshToken(Argument::type(RefreshTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $refreshTokenResult = $method->invoke($this->tokenGeneration, new AccessTokenEntity());

        $this->assertSame($refreshToken, $refreshTokenResult);
    }

    public function testIssueRefreshTokenNullToken(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn(null);

        $refreshTokenResult = $method->invoke($this->tokenGeneration, new AccessTokenEntity());

        $this->assertSame(null, $refreshTokenResult);
    }

    public function testIssueRefreshTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $refreshToken = new RefreshTokenEntity();
        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn($refreshToken);

        $this->refreshTokenRepositoryProphecy
            ->persistNewRefreshToken(Argument::type(RefreshTokenEntityInterface::class))
            ->shouldBeCalledTimes(5)
            ->willThrow(UniqueTokenIdentifierException::class);

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
        $method->invoke($this->tokenGeneration);
    }

    public function testGoodGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add(new DateInterval('P1M')));
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setIdentifier('REFRESH_TOKEN_ID');

        $this->assertSame($accessToken, $refreshToken->getAccessToken());

        /** @var ResponseInterface $responseResult */
        $responseResult = $method->invoke(
            $this->tokenGeneration,
            (new ResponseFactory())->createResponse(),
            $accessToken,
            $refreshToken
        );

        $this->assertSame(200, $responseResult->getStatusCode());
    }

    public function testJsonErrorRefreshTokenPayloadGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $refreshToken = new RefreshTokenEntity();
        $refreshToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add(new DateInterval('P1M')));
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->setIdentifier('REFRESH_TOKEN_ID');

        $GLOBALS['json_encode_false'] = true;

        $this->expectException(JsonEncodingException::class);
        $this->expectExceptionMessage('Error while JSON encoding the refresh token payload');
        $method->invoke($this->tokenGeneration, (new ResponseFactory())->createResponse(), $accessToken, $refreshToken);
    }

    public function testJsonErrorResponseParametersGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->tokenGeneration);
        $method = $class->getMethod('generateHttpResponse');
        $method->setAccessible(true);

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $accessToken->setExpiryDateTime((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')));
        $accessToken->setJwtConfiguration($this->jwtConfiguration);
        $accessToken->setIdentifier('ACCESS_TOKEN_ID');

        $GLOBALS['json_encode_false'] = true;

        $this->expectException(JsonEncodingException::class);
        $this->expectExceptionMessage('Error while JSON encoding response parameters');
        $method->invoke($this->tokenGeneration, (new ResponseFactory())->createResponse(), $accessToken, null);
    }

    public function testValidRespondToTokenRequest(): void
    {
        $parsedBody = [
            'username' => 'admin',
            'password' => 'pass'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->userRepositoryProphecy
            ->getUserEntityByUserCredentials('admin', 'pass')
            ->shouldBeCalledOnce()
            ->willReturn(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('1');
        $this->accessTokenRepositoryProphecy
            ->getNewToken('1')
            ->shouldBeCalledOnce()
            ->willReturn($accessToken);

        $this->accessTokenRepositoryProphecy
            ->persistNewAccessToken(Argument::type(AccessTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn(new RefreshTokenEntity());

        $this->refreshTokenRepositoryProphecy
            ->persistNewRefreshToken(Argument::type(RefreshTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $responseResult = $this->tokenGeneration->respondToTokenRequest(
            $serverRequest,
            (new ResponseFactory())->createResponse()
        );
        $this->assertSame(200, $responseResult->getStatusCode());
    }

    public function testNoUsername(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token');

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('username');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }

    public function testNoPassword(): void
    {
        $parsedBody = [
            'username' => 'admin'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('password');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }

    public function testBadIdentification(): void
    {
        $parsedBody = [
            'username' => 'admin',
            'password' => 'pass'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->userRepositoryProphecy
            ->getUserEntityByUserCredentials('admin', 'pass')
            ->shouldBeCalledOnce()
            ->willReturn(null);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid identification');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }

    public function testValidRespondToTokenRequestWithRefreshToken(): void
    {
        $refreshTokenPayload = json_encode([
            'refresh_token_id' => 'REFRESH_TOKEN_ID',
            'access_token_id'  => 'ACCESS_TOKEN_ID',
            'user_id'          => 'USER_ID',
            'expire_time'      => time() + 3600
        ]);
        $parsedBody = [
            'refresh_token' => Crypto::encrypt($refreshTokenPayload, $this->keyCrypt)
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->refreshTokenRepositoryProphecy
            ->isRefreshTokenRevoked('REFRESH_TOKEN_ID')
            ->shouldBeCalledOnce()
            ->willReturn(false);

        $this->accessTokenRepositoryProphecy
            ->revokeAccessToken('ACCESS_TOKEN_ID')
            ->shouldBeCalledOnce();

        $this->refreshTokenRepositoryProphecy
            ->revokeRefreshToken('REFRESH_TOKEN_ID')
            ->shouldBeCalledOnce();

        $accessToken = new AccessTokenEntity();
        $accessToken->setUserIdentifier('USER_ID');
        $this->accessTokenRepositoryProphecy
            ->getNewToken('USER_ID')
            ->shouldBeCalledOnce()
            ->willReturn($accessToken);

        $this->accessTokenRepositoryProphecy
            ->persistNewAccessToken(Argument::type(AccessTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn(new RefreshTokenEntity());

        $this->refreshTokenRepositoryProphecy
            ->persistNewRefreshToken(Argument::type(RefreshTokenEntityInterface::class))
            ->shouldBeCalledOnce();

        $responseResult = $this->tokenGeneration->respondToTokenRequest(
            $serverRequest,
            (new ResponseFactory())->createResponse()
        );
        $this->assertSame(200, $responseResult->getStatusCode());
    }

    public function testBadEncryptionRefreshToken(): void
    {
        $parsedBody = [
            'refresh_token' => 'BAD_REFRESH_TOKEN'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Cannot decrypt the refresh token');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }

    public function testExpiredRefreshToken(): void
    {
        $refreshTokenPayload = json_encode([
            'refresh_token_id' => 'REFRESH_TOKEN_ID',
            'access_token_id'  => 'ACCESS_TOKEN_ID',
            'user_id'          => 'USER_ID',
            'expire_time'      => time() - 1
        ]);
        $parsedBody = [
            'refresh_token' => Crypto::encrypt($refreshTokenPayload, $this->keyCrypt)
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Token has expired');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
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
            'refresh_token' => Crypto::encrypt($refreshTokenPayload, $this->keyCrypt)
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token')
            ->withParsedBody($parsedBody);

        $this->refreshTokenRepositoryProphecy
            ->isRefreshTokenRevoked('REFRESH_TOKEN_ID')
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $this->expectException(InvalidRefreshTokenException::class);
        $this->expectExceptionMessage('Token has been revoked');
        $this->tokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }
}
