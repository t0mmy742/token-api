<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenValidator;

use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;

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
            $token = $this->jwtConfiguration->parser()->parse($jwt);
        } catch (InvalidArgumentException $e) {
            throw new AccessDeniedException($e->getMessage(), 0, $e);
        } catch (RuntimeException $e) {
            throw new AccessDeniedException('Error while decoding from JSON', 0, $e);
        }

        if ($token instanceof Plain === false) {
            throw new AccessDeniedException('Error while parsing access token');
        }

        if (
            $this->jwtConfiguration->validator()->validate($token, new SignedWith(
                $this->jwtConfiguration->signer(),
                $this->jwtConfiguration->verificationKey()
            )) === false
        ) {
            throw new AccessDeniedException('Access token could not be verified');
        }

        if (
            $this->jwtConfiguration->validator()->validate(
                $token,
                new ValidAt(SystemClock::fromSystemTimezone())
            ) === false
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
