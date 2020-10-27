<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use Lcobucci\Jose\Parsing\Decoder;
use Lcobucci\Jose\Parsing\Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
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

        $this->accessTokenRepositoryInterface
            ->expects($this->once())
            ->method('isAccessTokenRevoked')
            ->with($token->claims()->get(RegisteredClaims::ID))
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
            ->willReturn($token);

        $this->expectException(AccessDeniedException::class);
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadJsonDecodingToken(): void
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

        $this->jwtConfiguration->setDecoder(new class implements Decoder {
            public function jsonDecode(string $json)
            {
                throw new Exception();
            }

            public function base64UrlDecode(string $data): string
            {
                return '';
            }
        });

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Error while decoding from JSON');
        $this->abstractTokenValidator->validateToken($serverRequest);
    }

    public function testBadParsingToken(): void
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

        $this->jwtConfiguration->setParser(new class implements Parser {
            public function parse(string $jwt): Token
            {
                return new class implements Token {
                    public function headers(): DataSet
                    {
                        return new DataSet([], '');
                    }

                    public function isPermittedFor(string $audience): bool
                    {
                        return true;
                    }

                    public function isIdentifiedBy(string $id): bool
                    {
                        return true;
                    }

                    public function isRelatedTo(string $subject): bool
                    {
                        return true;
                    }

                    public function hasBeenIssuedBy(string ...$issuers): bool
                    {
                        return true;
                    }

                    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
                    {
                        return true;
                    }

                    public function isMinimumTimeBefore(DateTimeInterface $now): bool
                    {
                        return true;
                    }

                    public function isExpired(DateTimeInterface $now): bool
                    {
                        return true;
                    }

                    public function __toString(): string
                    {
                        return '';
                    }
                };
            }
        });

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Error while parsing access token');
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
