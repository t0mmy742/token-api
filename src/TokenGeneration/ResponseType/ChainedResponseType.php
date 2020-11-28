<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\TokenGeneration\ResponseType;

use Psr\Http\Message\ResponseInterface;

class ChainedResponseType implements ResponseTypeInterface
{
    /** @var ResponseTypeInterface[] */
    private array $responseTypes;

    public function __construct(ResponseTypeInterface ...$responseTypes)
    {
        $this->responseTypes = $responseTypes;
    }

    public static function default(string $domain, bool $secure): self
    {
        return new self(new BearerResponseType(), new CookiesResponseType($domain, $secure));
    }

    public function completeResponse(
        ResponseInterface $response,
        string $accessToken,
        int $expirationAccessToken,
        ?string $refreshToken,
        ?int $expirationRefreshToken
    ): ResponseInterface {
        foreach ($this->responseTypes as $responseType) {
            $response = $responseType->completeResponse(
                $response,
                $accessToken,
                $expirationAccessToken,
                $refreshToken,
                $expirationRefreshToken
            );
        }

        return $response;
    }
}
