<?php

namespace Pterodactyl\Tests\Integration\Http\Controllers\Auth;

use Pterodactyl\Models\User;
use Illuminate\Support\Facades\Event;
use Pterodactyl\Events\Auth\DirectLogin;
use Pterodactyl\Services\Helpers\AssetHashService;
use Pterodactyl\Tests\Integration\Http\HttpTestCase;

class AuthenticateWithHttpHeaderTest extends HttpTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        Event::fake([DirectLogin::class]);

        $mockAssetHashService = \Mockery::mock(AssetHashService::class);
        $mockAssetHashService->shouldReceive('url')->andReturn('/test-asset.js');
        $mockAssetHashService->shouldReceive('integrity')->andReturn('sha256-mock');
        $mockAssetHashService->shouldReceive('css')->andReturn('');
        $mockAssetHashService->shouldReceive('js')->andReturn('');
        $this->app->instance(AssetHashService::class, $mockAssetHashService);
    }

    /**
     * Test that an existing user is authenticated via HTTP header and redirected from login page.
     */
    public function testExistingUserIsAuthenticatedViaHeader(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');
        config()->set('pterodactyl.auth.header.user_header', 'Remote-User');

        /** @var User $user */
        $user = User::factory()->create();

        $response = $this->withHeaders([
            'Remote-User' => $user->username,
        ])->get('/auth/login');

        $response->assertRedirect(route('index'));
        $this->assertAuthenticatedAs($user);

        Event::assertDispatched(fn (DirectLogin $event) => $event->user->is($user) && $event->remember);
    }

    /**
     * Test that a new user is automatically created and authenticated when header auth is enabled.
     */
    public function testNewUserIsAutomaticallyCreatedAndAuthenticated(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');
        config()->set('pterodactyl.auth.header.create_user', true);
        config()->set('pterodactyl.auth.header.user_header', 'Remote-User');
        config()->set('pterodactyl.auth.header.email_header', 'Remote-Email');
        config()->set('pterodactyl.auth.header.name_header', 'Remote-Name');

        $response = $this->withHeaders([
            'Remote-User' => 'sso-newuser',
            'Remote-Email' => 'sso-newuser@example.com',
            'Remote-Name' => 'Sammy Sso',
        ])->get('/auth/login');

        $response->assertRedirect(route('index'));

        /** @var User|null $user */
        $user = User::query()->where('username', 'sso-newuser')->first();
        $this->assertNotNull($user);
        $this->assertSame('sso-newuser@example.com', $user->email);
        $this->assertSame('Sammy', $user->name_first);
        $this->assertSame('Sso', $user->name_last);
        $this->assertFalse($user->root_admin);

        $this->assertAuthenticatedAs($user);
        Event::assertDispatched(fn (DirectLogin $event) => $event->user->is($user) && $event->remember);
    }

    /**
     * Test that request from an untrusted proxy is not authenticated.
     */
    public function testUntrustedProxyDoesNotAuthenticate(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '10.0.0.1');

        /** @var User $user */
        $user = User::factory()->create();

        $response = $this->withServerVariables([
            'REMOTE_ADDR' => '192.168.1.100',
        ])->withHeaders([
            'Remote-User' => $user->username,
        ])->get('/auth/login');

        $response->assertOk();
        $this->assertGuest();
        Event::assertNotDispatched(DirectLogin::class);
    }

    /**
     * Test that headers are ignored when header authentication is disabled.
     */
    public function testHeaderAuthDisabledDoesNotAuthenticate(): void
    {
        config()->set('pterodactyl.auth.header.enabled', false);

        /** @var User $user */
        $user = User::factory()->create();

        $response = $this->withHeaders([
            'Remote-User' => $user->username,
        ])->get('/auth/login');

        $response->assertOk();
        $this->assertGuest();
        Event::assertNotDispatched(DirectLogin::class);
    }

    /**
     * Test that session switches when a different identity is supplied in the headers.
     */
    public function testSwitchesUserWhenDifferentHeaderIdentitySupplied(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');

        /** @var User $user1 */
        $user1 = User::factory()->create();
        /** @var User $user2 */
        $user2 = User::factory()->create();

        $response = $this->actingAs($user1)->withHeaders([
            'Remote-User' => $user2->username,
        ])->get('/auth/login');

        $response->assertRedirect(route('index'));
        $this->assertAuthenticatedAs($user2);
    }

    /**
     * Test that user is not automatically created when create_user is disabled.
     */
    public function testNewUserIsNotCreatedWhenCreateUserIsDisabled(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');
        config()->set('pterodactyl.auth.header.create_user', false);
        config()->set('pterodactyl.auth.header.user_header', 'Remote-User');
        config()->set('pterodactyl.auth.header.email_header', 'Remote-Email');

        $response = $this->withHeaders([
            'Remote-User' => 'unknown-sso-user',
            'Remote-Email' => 'unknown@example.com',
        ])->get('/auth/login');

        $response->assertOk();
        $this->assertGuest();
        $this->assertNull(User::query()->where('username', 'unknown-sso-user')->first());
        Event::assertNotDispatched(DirectLogin::class);
    }

    /**
     * Test that existing user is found by email when the header username differs.
     */
    public function testExistingUserFoundByEmailWhenUsernameDiffers(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');
        config()->set('pterodactyl.auth.header.user_header', 'Remote-User');
        config()->set('pterodactyl.auth.header.email_header', 'Remote-Email');

        /** @var User $user */
        $user = User::factory()->create([
            'username' => 'original-username',
            'email' => 'original@example.com',
        ]);

        $response = $this->withHeaders([
            'Remote-User' => 'different-header-username',
            'Remote-Email' => 'original@example.com',
        ])->get('/auth/login');

        $response->assertRedirect(route('index'));
        $this->assertAuthenticatedAs($user);
        Event::assertDispatched(fn (DirectLogin $event) => $event->user->is($user) && $event->remember);
    }

    /**
     * Test that logout passes through and logs out user even with headers present.
     */
    public function testLogoutPassesThroughWithoutReauthenticating(): void
    {
        config()->set('pterodactyl.auth.header.enabled', true);
        config()->set('pterodactyl.auth.header.trusted_proxies', '*');
        config()->set('pterodactyl.auth.header.user_header', 'Remote-User');

        /** @var User $user */
        $user = User::factory()->create();

        $response = $this->actingAs($user)->withHeaders([
            'Remote-User' => $user->username,
        ])->post('/auth/logout');

        $response->assertNoContent();
        $this->assertGuest();
    }
}
