<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Jose\Parsing\Decoder;
use Lcobucci\Jose\Parsing\Exception;
use Lcobucci\JWT\Configuration;
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
            new Key('file://' . __DIR__ . '/../Stubs/private.key'),
            new Key('file://' . __DIR__ . '/../Stubs/public.key')
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

        $decoder = $this->createStub(Decoder::class);
        $decoder
            ->method('jsonDecode')
            ->willThrowException(new Exception());
        $this->jwtConfiguration->setDecoder($decoder);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Error while decoding from JSON');
        $this->expectExceptionCode(0);
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadParsingToken(): void
    {
        $serverRequest = $this->createStub(ServerRequestInterface::class);

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
        $serverRequest = $this->createStub(ServerRequestInterface::class);

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
        $serverRequest = $this->createStub(ServerRequestInterface::class);

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
