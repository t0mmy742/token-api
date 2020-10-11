<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\TokenGeneration;

use DateInterval;
use DateTimeImmutable;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key as KeyCrypt;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use t0mmy742\TokenAPI\Entities\AccessTokenEntityInterface;
use t0mmy742\TokenAPI\Entities\RefreshTokenEntityInterface;
use t0mmy742\TokenAPI\Exception\InvalidRefreshTokenException;
use t0mmy742\TokenAPI\Exception\InvalidRequestException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\RefreshTokenRepositoryInterface;
use t0mmy742\TokenAPI\Repository\UserRepositoryInterface;
use t0mmy742\TokenAPI\Tests\Stubs\AccessTokenEntity;
use t0mmy742\TokenAPI\Tests\Stubs\RefreshTokenEntity;
use t0mmy742\TokenAPI\Tests\TestCase;
use t0mmy742\TokenAPI\TokenGeneration\RefreshTokenGeneration;

use function json_encode;
use function time;

class RefreshTokenGenerationTest extends TestCase
{
    private RefreshTokenGeneration $refreshTokenGeneration;
    private ObjectProphecy $userRepositoryProphecy;
    private ObjectProphecy $refreshTokenRepositoryProphecy;
    private ObjectProphecy $accessTokenRepositoryProphecy;
    private KeyCrypt $keyCrypt;

    protected function setUp(): void
    {
        $this->userRepositoryProphecy = $this->prophesize(UserRepositoryInterface::class);
        $this->refreshTokenRepositoryProphecy = $this->prophesize(RefreshTokenRepositoryInterface::class);
        $this->accessTokenRepositoryProphecy = $this->prophesize(AccessTokenRepositoryInterface::class);
        $this->keyCrypt = KeyCrypt::createNewRandomKey();

        $this->refreshTokenGeneration = new RefreshTokenGeneration(
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
            $this->keyCrypt
        );
    }

    public function testValidRespondToTokenRequest(): void
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

        //TODO
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

        $responseResult = $this->refreshTokenGeneration->respondToTokenRequest(
            $serverRequest,
            (new ResponseFactory())->createResponse()
        );
        $this->assertSame(200, $responseResult->getStatusCode());
    }

    public function testNoRefreshToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('POST', '/token');

        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('refresh_token');
        $this->refreshTokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
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
        $this->refreshTokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
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
        $this->refreshTokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
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
        $this->refreshTokenGeneration->respondToTokenRequest($serverRequest, (new ResponseFactory())->createResponse());
    }
}
