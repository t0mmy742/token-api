<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\Tests\TokenValidator;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\RegisteredClaims;
use Prophecy\Prophecy\ObjectProphecy;
use Slim\Psr7\Factory\ServerRequestFactory;
use t0mmy742\TokenAPI\Exception\AccessDeniedException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use t0mmy742\TokenAPI\Tests\TestCase;
use t0mmy742\TokenAPI\TokenValidator\AbstractTokenValidator;

class AbstractTokenValidatorTest extends TestCase
{
    private AbstractTokenValidator $abstractTokenValidator;
    private ObjectProphecy $accessTokenRepositoryInterfaceProphecy;
    private Configuration $jwtConfiguration;

    protected function setUp(): void
    {
        $this->accessTokenRepositoryInterfaceProphecy = $this->prophesize(AccessTokenRepositoryInterface::class);

        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            new Key('file://' . __DIR__ . '/../Stubs/private.key'),
            new Key('file://' . __DIR__ . '/../Stubs/public.key')
        );

        $this->abstractTokenValidator = $this->getMockForAbstractClass(AbstractTokenValidator::class, [
            $this->accessTokenRepositoryInterfaceProphecy->reveal(),
            $this->jwtConfiguration
        ]);
    }

    public function testValidToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $token = $this->jwtConfiguration->createBuilder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable('@' . time()))
            ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . time()))
            ->expiresAt((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->getSigner(), $this->jwtConfiguration->getSigningKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn((string) $token);

        $this->accessTokenRepositoryInterfaceProphecy
            ->isAccessTokenRevoked($token->claims()->get(RegisteredClaims::ID))
            ->shouldBeCalledOnce()
            ->willReturn(false);

        $serverRequest = $this->abstractTokenValidator->validateToken($serverRequest);

        $this->assertSame($serverRequest->getAttribute('access_token_id'), 'TOKEN_ID');
        $this->assertSame($serverRequest->getAttribute('user_id'), 'USER_ID');
    }

    public function testNotAToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $token = 'MY_BAD_TOKEN';

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn((string) $token);

        $this->expectException(AccessDeniedException::class);
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadSignerToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $token = $this->jwtConfiguration->createBuilder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable('@' . time()))
            ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . time()))
            ->expiresAt((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken(new None(), new Key(''));

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn((string) $token);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token could not be verified');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testExpiredToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $token = $this->jwtConfiguration->createBuilder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable('@' . time()))
            ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . time()))
            ->expiresAt((new DateTimeImmutable('@' . time()))->sub(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->getSigner(), $this->jwtConfiguration->getSigningKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn((string) $token);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token is invalid');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testRevokedToken(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $token = $this->jwtConfiguration->createBuilder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable('@' . time()))
            ->canOnlyBeUsedAfter(new DateTimeImmutable('@' . time()))
            ->expiresAt((new DateTimeImmutable('@' . time()))->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->getSigner(), $this->jwtConfiguration->getSigningKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn((string) $token);

        $this->accessTokenRepositoryInterfaceProphecy
            ->isAccessTokenRevoked($token->claims()->get(RegisteredClaims::ID))
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token has been revoked');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }
}
