<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator;

use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPI\Tests\TestCase;
use T0mmy742\TokenAPI\TokenValidator\BearerAuthorizationHeaderTokenValidator;

class BearerAuthorizationHeaderTokenValidatorTest extends TestCase
{
    private function retrieveTokenMethod(ServerRequestInterface $request): string
    {
        $bearerAuthorizationHeaderTokenValidator = new BearerAuthorizationHeaderTokenValidator(
            $this->prophesize(AccessTokenRepositoryInterface::class)->reveal(),
            Configuration::forUnsecuredSigner()
        );
        $class = new ReflectionClass($bearerAuthorizationHeaderTokenValidator);
        $method = $class->getMethod('retrieveToken');
        $method->setAccessible(true);

        return $method->invoke($bearerAuthorizationHeaderTokenValidator, $request);
    }

    public function testGoodHeader(): void
    {
        $token = 'MY_TOKEN';

        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test')
            ->withHeader('Authorization', 'Bearer ' . $token);

        $tokenResult = $this->retrieveTokenMethod($serverRequest);

        $this->assertSame($token, $tokenResult);
    }

    public function testNoHeader(): void
    {
        $serverRequest = (new ServerRequestFactory())->createServerRequest('GET', '/test');

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Missing "Authorization" header');
        $this->retrieveTokenMethod($serverRequest);
    }
}
