<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;

use function time;

abstract class AbstractTokenValidator implements TokenValidatorInterface
{
    private AccessTokenRepositoryInterface $accessTokenRepository;
    private Configuration $jwtConfiguration;

    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, Configuration $jwtConfiguration)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->jwtConfiguration = $jwtConfiguration;
    }

    public function validateToken(ServerRequestInterface $request): ServerRequestInterface
    {
        $jwt = $this->retrieveToken($request);

        try {
            $token = $this->jwtConfiguration->getParser()->parse($jwt);
        } catch (InvalidArgumentException $e) {
            throw new AccessDeniedException($e->getMessage());
        } catch (RuntimeException $e) {
            throw new AccessDeniedException('Error while decoding from JSON');
        }

        if ($token instanceof Plain === false) {
            throw new AccessDeniedException('Error while parsing access token');
        }

        if (
            $this->jwtConfiguration->getValidator()->validate($token, new SignedWith(
                $this->jwtConfiguration->getSigner(),
                $this->jwtConfiguration->getVerificationKey()
            )) === false
        ) {
            throw new AccessDeniedException('Access token could not be verified');
        }

        if (
            $this->jwtConfiguration->getValidator()->validate($token, new ValidAt(
                new FrozenClock(new DateTimeImmutable('@' . time()))
            )) === false
        ) {
            throw new AccessDeniedException('Access token is invalid');
        }

        if ($this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get(RegisteredClaims::ID))) {
            throw new AccessDeniedException('Access token has been revoked');
        }

        return $request
            ->withAttribute('access_token_id', $token->claims()->get(RegisteredClaims::ID))
            ->withAttribute('user_id', $token->claims()->get(RegisteredClaims::SUBJECT));
    }

    abstract protected function retrieveToken(ServerRequestInterface $request): string;
}
