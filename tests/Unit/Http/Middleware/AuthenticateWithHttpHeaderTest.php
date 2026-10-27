<?php

namespace Pterodactyl\Tests\Unit\Http\Middleware;

use Mockery as m;
use Mockery\MockInterface;
use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Config;
use Pterodactyl\Events\Auth\DirectLogin;
use Illuminate\Contracts\Session\Session;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Http\Middleware\AuthenticateWithHttpHeader;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;

class AuthenticateWithHttpHeaderTest extends MiddlewareTestCase
{
    private MockInterface $auth;
    private MockInterface $guard;
    private MockInterface $userRepository;
    private MockInterface $userCreationService;

    public function setUp(): void
    {
        parent::setUp();

        Event::fake([DirectLogin::class]);

        $this->auth = m::mock(AuthManager::class);
        $this->guard = m::mock(Guard::class);
        $this->userRepository = m::mock(UserRepositoryInterface::class);
        $this->userCreationService = m::mock(UserCreationService::class);

        $this->auth->shouldReceive('guard')->byDefault()->andReturn($this->guard);
    }

    /**
     * Test that request passes through when header authentication is disabled.
     */
    public function testPassesThroughWhenDisabled(): void
    {
        Config::set('pterodactyl.auth.header.enabled', false);

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that request to logout route passes through without re-authenticating.
     */
    public function testPassesThroughOnLogoutRoute(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(true);

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that request without the user header passes through.
     */
    public function testPassesThroughWhenNoUserHeader(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.trusted_proxies', null);
        Config::set('trustedproxy.proxies', null);

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturnNull();
        $this->request->shouldReceive('server')->with('REMOTE_USER')->andReturnNull();
        $this->request->shouldReceive('server')->with('HTTP_REMOTE_USER')->andReturnNull();
        $this->request->shouldReceive('server')->with('REDIRECT_REMOTE_USER')->andReturnNull();
        $this->request->shouldReceive('server')->with('REDIRECT_HTTP_REMOTE_USER')->andReturnNull();

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that untrusted proxy request is rejected from header auth.
     */
    public function testRejectsUntrustedProxy(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.trusted_proxies', '10.0.0.1,192.168.1.0/24');

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('server')->with('REMOTE_ADDR')->andReturn('172.16.0.50');

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that already authenticated matching user passes through without re-authenticating.
     */
    public function testPassesThroughForMatchingCurrentUser(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $currentUser = new User();
        $currentUser->username = 'alice';
        $currentUser->email = 'alice@example.com';

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('alice');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('alice@example.com');
        $this->request->shouldReceive('user')->andReturn($currentUser);

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that user switching occurs when a different user is in header.
     */
    public function testSwitchesUserWhenDifferentIdentityProvided(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');
        Config::set('pterodactyl.auth.header.create_user', false);

        $currentUser = new User();
        $currentUser->username = 'alice';
        $currentUser->email = 'alice@example.com';

        $session = m::mock(Session::class);
        $session->shouldReceive('invalidate')->once();
        $session->shouldReceive('regenerateToken')->once();

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('bob');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('bob@example.com');
        $this->request->shouldReceive('user')->andReturn($currentUser);
        $this->request->shouldReceive('hasSession')->andReturn(true);
        $this->request->shouldReceive('session')->andReturn($session);

        $this->guard->shouldReceive('logout')->once();

        $this->userRepository->shouldReceive('findFirstWhere')->with(['username' => 'bob'])->once()->andThrow(new RecordNotFoundException());
        $this->userRepository->shouldReceive('findFirstWhere')->with(['email' => 'bob@example.com'])->once()->andThrow(new RecordNotFoundException());

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test reading headers from HTTP_ prefixed server variables.
     */
    public function testReadsHeadersFromServerVariables(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $currentUser = new User();
        $currentUser->username = 'proxyuser';
        $currentUser->email = 'proxyuser@example.com';

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturnNull();
        $this->request->shouldReceive('server')->with('REMOTE_USER')->andReturnNull();
        $this->request->shouldReceive('server')->with('HTTP_REMOTE_USER')->andReturn('proxyuser');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturnNull();
        $this->request->shouldReceive('server')->with('REMOTE_EMAIL')->andReturnNull();
        $this->request->shouldReceive('server')->with('HTTP_REMOTE_EMAIL')->andReturn('proxyuser@example.com');
        $this->request->shouldReceive('user')->andReturn($currentUser);

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test user is authenticated and logged in when user exists.
     */
    public function testAuthenticatesExistingUser(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $existingUser = new User();
        $existingUser->username = 'carol';
        $existingUser->email = 'carol@example.com';

        $session = m::mock(Session::class);
        $session->shouldReceive('regenerate')->once();

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('carol');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('carol@example.com');
        $this->request->shouldReceive('user')->andReturnNull();
        $this->request->shouldReceive('hasSession')->andReturn(true);
        $this->request->shouldReceive('session')->andReturn($session);
        $this->request->shouldReceive('setUserResolver')->once();

        $this->userRepository->shouldReceive('findFirstWhere')->with(['username' => 'carol'])->once()->andReturn($existingUser);

        $this->guard->shouldReceive('login')->with($existingUser, true)->once();

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());

        Event::assertDispatched(fn (DirectLogin $e) => $e->user === $existingUser && $e->remember);
    }

    /**
     * Test user is automatically created when user does not exist and create_user is true.
     */
    public function testCreatesUserAutomaticallyWhenConfigured(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.name_header', 'Remote-Name');
        Config::set('pterodactyl.auth.header.create_user', true);
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $newUser = new User();
        $newUser->username = 'dave';
        $newUser->email = 'dave@example.com';

        $session = m::mock(Session::class);
        $session->shouldReceive('regenerate')->once();

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('dave');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('dave@example.com');
        $this->request->shouldReceive('header')->with('Remote-Name')->andReturn('Dave Miller');
        $this->request->shouldReceive('user')->andReturnNull();
        $this->request->shouldReceive('hasSession')->andReturn(true);
        $this->request->shouldReceive('session')->andReturn($session);
        $this->request->shouldReceive('setUserResolver')->once();

        $this->userRepository->shouldReceive('findFirstWhere')->with(['username' => 'dave'])->once()->andThrow(new RecordNotFoundException());
        $this->userRepository->shouldReceive('findFirstWhere')->with(['email' => 'dave@example.com'])->once()->andThrow(new RecordNotFoundException());

        $this->userCreationService->shouldReceive('handle')->with([
            'email' => 'dave@example.com',
            'username' => 'dave',
            'name_first' => 'Dave',
            'name_last' => 'Miller',
            'root_admin' => false,
        ])->once()->andReturn($newUser);

        $this->guard->shouldReceive('login')->with($newUser, true)->once();

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());

        Event::assertDispatched(fn (DirectLogin $e) => $e->user === $newUser && $e->remember);
    }

    /**
     * Test that user is not created and request passes through when user does not exist and create_user is false.
     */
    public function testDoesNotCreateUserWhenCreateUserIsDisabled(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.create_user', false);
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('unknown');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('unknown@example.com');
        $this->request->shouldReceive('user')->andReturnNull();

        $this->userRepository->shouldReceive('findFirstWhere')->with(['username' => 'unknown'])->once()->andThrow(new RecordNotFoundException());
        $this->userRepository->shouldReceive('findFirstWhere')->with(['email' => 'unknown@example.com'])->once()->andThrow(new RecordNotFoundException());

        $this->userCreationService->shouldNotReceive('handle');
        $this->guard->shouldNotReceive('login');

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());
    }

    /**
     * Test that existing user is authenticated when located via email fallback.
     */
    public function testAuthenticatesExistingUserFoundByEmail(): void
    {
        Config::set('pterodactyl.auth.header.enabled', true);
        Config::set('pterodactyl.auth.header.user_header', 'Remote-User');
        Config::set('pterodactyl.auth.header.email_header', 'Remote-Email');
        Config::set('pterodactyl.auth.header.trusted_proxies', '*');

        $existingUser = new User();
        $existingUser->username = 'original_user';
        $existingUser->email = 'matching@example.com';

        $session = m::mock(Session::class);
        $session->shouldReceive('regenerate')->once();

        $this->request->shouldReceive('is')->with('auth/logout', 'logout')->once()->andReturn(false);
        $this->request->shouldReceive('route')->andReturnNull();
        $this->request->shouldReceive('header')->with('Remote-User')->andReturn('sso_prefix');
        $this->request->shouldReceive('header')->with('Remote-Email')->andReturn('matching@example.com');
        $this->request->shouldReceive('user')->andReturnNull();
        $this->request->shouldReceive('hasSession')->andReturn(true);
        $this->request->shouldReceive('session')->andReturn($session);
        $this->request->shouldReceive('setUserResolver')->once();

        $this->userRepository->shouldReceive('findFirstWhere')->with(['username' => 'sso_prefix'])->once()->andThrow(new RecordNotFoundException());
        $this->userRepository->shouldReceive('findFirstWhere')->with(['email' => 'matching@example.com'])->once()->andReturn($existingUser);

        $this->guard->shouldReceive('login')->with($existingUser, true)->once();

        $this->getMiddleware()->handle($this->request, $this->getClosureAssertions());

        Event::assertDispatched(fn (DirectLogin $e) => $e->user === $existingUser && $e->remember);
    }

    private function getMiddleware(): AuthenticateWithHttpHeader
    {
        return new AuthenticateWithHttpHeader($this->auth, $this->userRepository, $this->userCreationService);
    }
}
