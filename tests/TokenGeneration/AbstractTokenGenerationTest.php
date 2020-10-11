<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Key as KeyCrypt;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ResponseInterface;
use ReflectionClass;
use Slim\Psr7\Factory\ResponseFactory;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use t0mmy742\TokenAPI\Tests\Stubs\AccessTokenEntity;
use t0mmy742\TokenAPI\Tests\Stubs\RefreshTokenEntity;
use t0mmy742\TokenAPI\Tests\TestCase;
use t0mmy742\TokenAPI\TokenGeneration\AbstractTokenGeneration;

class AbstractTokenGenerationTest extends TestCase
{
    private AbstractTokenGeneration $abstractTokenGeneration;
    private ObjectProphecy $refreshTokenRepositoryProphecy;
    private ObjectProphecy $accessTokenRepositoryProphecy;
    private Configuration $jwtConfiguration;

    protected function setUp(): void
    {
        $this->refreshTokenRepositoryProphecy = $this->prophesize(RefreshTokenRepositoryInterface::class);
        $this->accessTokenRepositoryProphecy = $this->prophesize(AccessTokenRepositoryInterface::class);
        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../Stubs/private.key'),
            new Key('file://' . __DIR__ . '/../Stubs/public.key')
        );

        $this->abstractTokenGeneration = $this->getMockForAbstractClass(AbstractTokenGeneration::class, [
            $this->prophesize(UserRepositoryInterface::class)->reveal(),
            $this->refreshTokenRepositoryProphecy->reveal(),
            new DateInterval('PT1H'),
            new DateInterval('P1M'),
            $this->accessTokenRepositoryProphecy->reveal(),
            $this->jwtConfiguration,
            KeyCrypt::createNewRandomKey()
        ]);
    }

    public function testGoodIssueAccessToken(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
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

        $accessTokenResult = $method->invoke($this->abstractTokenGeneration, new DateInterval('PT1H'), '1');

        $this->assertSame($accessToken, $accessTokenResult);
    }

    public function testIssueAccessTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
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
        $method->invoke($this->abstractTokenGeneration, new DateInterval('PT1H'), '1');
    }

    public function testGoodIssueRefreshToken(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
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

        $refreshTokenResult = $method->invoke($this->abstractTokenGeneration, new AccessTokenEntity());

        $this->assertSame($refreshToken, $refreshTokenResult);
    }

    public function testIssueRefreshTokenNullToken(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
        $method = $class->getMethod('issueRefreshToken');
        $method->setAccessible(true);

        $this->refreshTokenRepositoryProphecy
            ->getNewRefreshToken()
            ->shouldBeCalledOnce()
            ->willReturn(null);

        $refreshTokenResult = $method->invoke($this->abstractTokenGeneration, new AccessTokenEntity());

        $this->assertSame(null, $refreshTokenResult);
    }

    public function testIssueRefreshTokenErrorOnPersist(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
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
        $method->invoke($this->abstractTokenGeneration, new AccessTokenEntity());
    }

    public function testGoodGenerateHttpResponse(): void
    {
        $class = new ReflectionClass($this->abstractTokenGeneration);
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

        /** @var ResponseInterface $responseResult */
        $responseResult = $method->invoke(
            $this->abstractTokenGeneration,
            (new ResponseFactory())->createResponse(),
            $accessToken,
            $refreshToken
        );

        $this->assertSame(200, $responseResult->getStatusCode());
    }
}
