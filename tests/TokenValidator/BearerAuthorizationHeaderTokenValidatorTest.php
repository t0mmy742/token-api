<?php

declare(strict_types=1);

namespace T0mmy742\TokenAPI\Tests\TokenValidator;

use Lcobucci\JWT\Configuration;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use Slim\Psr7\Factory\ServerRequestFactory;
use T0mmy742\TokenAPI\Exception\AccessDeniedException;
use T0mmy742\TokenAPI\Repository\AccessTokenRepositoryInterface;
use T0mmy742\TokenAPI\TokenValidator\BearerAuthorizationHeaderTokenValidator;

class BearerAuthorizationHeaderTokenValidatorTest extends TestCase
{
    private function retrieveTokenMethod(ServerRequestInterface $request): string
    {
        $bearerAuthorizationHeaderTokenValidator = new BearerAuthorizationHeaderTokenValidator(
            $this->createStub(AccessTokenRepositoryInterface::class),
            $this->createStub(Configuration::class)
        );
        $class = new ReflectionClass($bearerAuthorizationHeaderTokenValidator);
        $method = $class->getMethod('retrieveToken');
        $method->setAccessible(true);

        return $method->invoke($bearerAuthorizationHeaderTokenValidator, $request);
    }

    public function testGoodHeader(): void
    {
        $token = 'MY_TOKEN';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenResult = $this->retrieveTokenMethod($serverRequest);

        $this->assertSame($token, $tokenResult);
    }

    public function testUntrimmedHeader(): void
    {
        $token = ' MY_TOKEN ';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $tokenResult = $this->retrieveTokenMethod($serverRequest);

        $this->assertSame(trim($token), $tokenResult);
    }

    public function testNoHeader(): void
    {
        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(false);

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessage('Missing "Authorization" header');
        $this->retrieveTokenMethod($serverRequest);
    }

    public function testErrorPregReplace(): void
    {
        $token = 'MY_TOKEN';

        $serverRequest = $this->createMock(ServerRequestInterface::class);
        $serverRequest
            ->expects($this->once())
            ->method('hasHeader')
            ->with('Authorization')
            ->willReturn(true);
        $serverRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('Authorization')
            ->willReturn(['Bearer ' . $token]);

        $GLOBALS['preg_replace_null'] = true;

        $tokenResult = $this->retrieveTokenMethod($serverRequest);

        $this->assertEquals('', $tokenResult);
    }
}
