<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\TokenGeneration;

use DateInterval;
use Defuse\Crypto\Key as KeyCrypt;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use ReflectionClass;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Exception\InvalidRequestException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use t0mmy742\TokenAPI\Tests\Stubs\AccessTokenEntity;
use t0mmy742\TokenAPI\Tests\Stubs\RefreshTokenEntity;
use t0mmy742\TokenAPI\Tests\Stubs\UserEntity;
use t0mmy742\TokenAPI\Tests\TestCase;
use t0mmy742\TokenAPI\TokenGeneration\AccessTokenGeneration;

class AccessTokenGenerationTest extends TestCase
{
    private AccessTokenGeneration $accessTokenGeneration;
    private ObjectProphecy $userRepositoryProphecy;
    private ObjectProphecy $refreshTokenRepositoryProphecy;
    private ObjectProphecy $accessTokenRepositoryProphecy;

    protected function setUp(): void
    {
        $this->userRepositoryProphecy = $this->prophesize(UserRepositoryInterface::class);
        $this->refreshTokenRepositoryProphecy = $this->prophesize(RefreshTokenRepositoryInterface::class);
        $this->accessTokenRepositoryProphecy = $this->prophesize(AccessTokenRepositoryInterface::class);

        $this->accessTokenGeneration = new AccessTokenGeneration(
            $this->userRepositoryProphecy->reveal(),
            $this->refreshTokenRepositoryProphecy->reveal(),
            new DateInterval('PT1H'),
            new DateInterval('P1M'),
            $this->accessTokenRepositoryProphecy->reveal(),
            Configuration::forAsymmetricSigner(
                new Sha256(),
                new Key('file://' . __DIR__ . '/../Stubs/private.key'),
                new Key('file://' . __DIR__ . '/../Stubs/public.key')
            ),
            KeyCrypt::createNewRandomKey()
        );
    }

    public function testValidRespondToTokenRequest(): void
    {
        $parsedBody = [
            'username' => 'admin',
            'password' => 'pass'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test')
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

        $responseResult = $this->accessTokenGeneration->respondToTokenRequest(
            $serverRequest,
            (new ResponseFactory())->createResponse()
        );
        $this->assertSame(200, $responseResult->getStatusCode());
    }

    public function testNoUsername(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $class = new ReflectionClass($this->accessTokenGeneration);
        $method = $class->getMethod('validateUser');
        $method->setAccessible(true);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('username');
        $method->invoke($this->accessTokenGeneration, $serverRequest);
    }

    public function testNoPassword(): void
    {
        $parsedBody = [
            'username' => 'admin'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test')
            ->withParsedBody($parsedBody);

        $class = new ReflectionClass($this->accessTokenGeneration);
        $method = $class->getMethod('validateUser');
        $method->setAccessible(true);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('password');
        $method->invoke($this->accessTokenGeneration, $serverRequest);
    }

    public function testBadIdentification(): void
    {
        $parsedBody = [
            'username' => 'admin',
            'password' => 'pass'
        ];
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test')
            ->withParsedBody($parsedBody);

        $this->userRepositoryProphecy
            ->getUserEntityByUserCredentials('admin', 'pass')
            ->shouldBeCalledOnce()
            ->willReturn(null);

        $class = new ReflectionClass($this->accessTokenGeneration);
        $method = $class->getMethod('validateUser');
        $method->setAccessible(true);

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('Invalid identification');
        $method->invoke($this->accessTokenGeneration, $serverRequest);
    }
}
