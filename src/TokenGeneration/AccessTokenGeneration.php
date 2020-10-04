<?php

declare(strict_types=1);

namespace t0mmy742\TokenAPI\TokenGeneration;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use t0mmy742\TokenAPI\Entities\UserEntityInterface;
use t0mmy742\TokenAPI\Exception\EncryptionException;
use t0mmy742\TokenAPI\Exception\InvalidRequestException;
use t0mmy742\TokenAPI\Exception\JsonEncodingException;
use t0mmy742\TokenAPI\Exception\RandomGenerationException;
use t0mmy742\TokenAPI\Exception\UniqueTokenIdentifierException;

class AccessTokenGeneration extends AbstractTokenGeneration
{
    /**
     * Respond to access token generation request, validating the parameters of the request.
     *
     * If the generation is successful, a Response will be returned.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * @throws EncryptionException
     * @throws InvalidRequestException
     * @throws JsonEncodingException
     * @throws RandomGenerationException
     * @throws UniqueTokenIdentifierException
     */
    public function respondToTokenRequest(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $user = $this->validateUser($request);

        $accessToken = $this->issueAccessToken($this->accessTokenTTL, $user->getIdentifier());

        $refreshToken = $this->issueRefreshToken($accessToken);

        return $this->generateHttpResponse($response, $accessToken, $refreshToken);
    }

    /**
     * Validate request parameters used for user identification.
     *
     * If the validation is successful, a UserEntity will be returned.
     *
     * @param ServerRequestInterface $request
     * @return UserEntityInterface
     * @throws InvalidRequestException
     */
    private function validateUser(ServerRequestInterface $request): UserEntityInterface
    {
        $requestParameters = (array) $request->getParsedBody();

        $username = $requestParameters['username'] ?? null;
        if ($username === null) {
            throw new InvalidRequestException('username');
        }

        $password = $requestParameters['password'] ?? null;
        if ($password === null) {
            throw new InvalidRequestException('password');
        }

        $user = $this->userRepository->getUserEntityByUserCredentials($username, $password);
        if ($user instanceof UserEntityInterface === false) {
            throw new InvalidRequestException('Invalid identification');
        }

        return $user;
    }
}
