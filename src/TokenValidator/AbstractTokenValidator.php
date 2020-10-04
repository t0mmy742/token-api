<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenValidator;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use t0mmy742\TokenAPI\Exception\AccessDeniedException;
use t0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;

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

            if ($token instanceof Plain === false) {
                throw new AccessDeniedException('Error while parsing access token');
            }

            if (
                $this->jwtConfiguration->getValidator()->validate($token, new SignedWith(
                    $this->jwtConfiguration->getSigner(),
                    $this->jwtConfiguration->getSigningKey()
                )) === false
            ) {
                throw new AccessDeniedException('Access token could not be verified');
            }

            if (
                $this->jwtConfiguration->getValidator()->validate($token, new ValidAt(
                    new FrozenClock(new DateTimeImmutable())
                )) === false
            ) {
                throw new AccessDeniedException('Access token is invalid');
            }
        } catch (InvalidArgumentException $e) {
            throw new AccessDeniedException($e->getMessage());
        } catch (RuntimeException $e) {
            throw new AccessDeniedException('Error while decoding to JSON');
        }

        if ($this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get('jti'))) {
            throw new AccessDeniedException('Access token has been revoked');
        }

        return $request
            ->withAttribute('access_token_id', $token->claims()->get('jti'))
            ->withAttribute('user_id', $token->claims()->get('sub'));
    }

    abstract protected function retrieveToken(ServerRequestInterface $request): string;
}
