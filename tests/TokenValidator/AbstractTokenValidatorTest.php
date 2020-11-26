<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPI\TokenValidator\AbstractTokenValidator;

class AbstractTokenValidatorTest extends TestCase
{
    /** @var AbstractTokenValidator&MockObject */
    private AbstractTokenValidator $abstractTokenValidator;
    /** @var AccessTokenRepositoryInterface&MockObject */
    private AccessTokenRepositoryInterface $accessTokenRepositoryInterface;
    private Configuration $jwtConfiguration;

    protected function setUp(): void
    {
        $this->accessTokenRepositoryInterface = $this->createMock(AccessTokenRepositoryInterface::class);

        $this->jwtConfiguration = Configuration::forAsymmetricSigner(
            new Sha256(),
            Key\LocalFileReference::file(__DIR__ . '/../Stubs/private.key'),
            Key\LocalFileReference::file(__DIR__ . '/../Stubs/public.key')
        );

        $this->abstractTokenValidator = $this->getMockForAbstractClass(AbstractTokenValidator::class, [
            $this->accessTokenRepositoryInterface,
            $this->jwtConfiguration
        ]);
    }

    public function testValidToken(): void
    {
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->exactly(2))
            ->method('withAttribute')
            ->withConsecutive(['access_token_id', 'TOKEN_ID'], ['user_id', 'USER_ID'])
            ->willReturn($serverRequest);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $this->accessTokenRepositoryInterface
            ->expects($this->once())
            ->method('isAccessTokenRevoked')
            ->with($token->claims()->get(RegisteredClaims::ID))
            ->willReturn(false);

        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testNotAToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = 'MY_BAD_TOKEN';

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionCode(0);
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadJsonDecodingToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $decoder = $this->createStub(Decoder::class);
        $decoder
            ->method('jsonDecode')
            ->willThrowException(new CannotDecodeContent());
        $this->jwtConfiguration->setParser(new Token\Parser($decoder));

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Error while decoding from JSON');
        $this->expectExceptionCode(0);
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadParsingToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $parser = $this->createStub(Parser::class);
        $parser
            ->method('parse')
            ->willReturn($this->createStub(Token::class));
        $this->jwtConfiguration->setParser($parser);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Error while parsing access token');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadSignerToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken(new None(), Key\InMemory::empty());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token could not be verified');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testExpiredToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->sub(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token is invalid');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testRevokedToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

        $token = $this->jwtConfiguration->builder()
            ->identifiedBy('TOKEN_ID')
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt((new DateTimeImmutable())->add(new DateInterval('PT1H')))
            ->relatedTo('USER_ID')
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());

        $this->abstractTokenValidator
            ->expects($this->once())
            ->method('retrieveToken')
            ->willReturn($token->toString());

        $this->accessTokenRepositoryInterface
            ->expects($this->once())
            ->method('isAccessTokenRevoked')
            ->with($token->claims()->get(RegisteredClaims::ID))
            ->willReturn(true);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Access token has been revoked');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }
}
