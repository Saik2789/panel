<?php

namespace Pterodactyl\Http\Middleware;

use Illuminate\Http\Request;
use Pterodactyl\Models\User;
use Illuminate\Auth\AuthManager;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Event;
use Pterodactyl\Events\Auth\DirectLogin;
use Symfony\Component\HttpFoundation\IpUtils;
use Pterodactyl\Services\Users\UserCreationService;
use Pterodactyl\Contracts\Repository\UserRepositoryInterface;
use Pterodactyl\Exceptions\Repository\RecordNotFoundException;

class AuthenticateWithHttpHeader
{
    /**
     * AuthenticateWithHttpHeader constructor.
     */
    public function __construct(
        private AuthManager $auth,
        private UserRepositoryInterface $userRepository,
        private UserCreationService $userCreationService,
    ) {
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        if (!config('pterodactyl.auth.header.enabled', false)) {
            return $next($request);
        }

        if ($request->is('auth/logout', 'logout') || ($request->route() && $request->route()->named('auth.logout'))) {
            return $next($request);
        }

        if (!$this->isTrustedRequest($request)) {
            return $next($request);
        }

        $userHeader = config('pterodactyl.auth.header.user_header', 'Remote-User');
        $rawUser = $this->getHeaderValue($request, $userHeader);

        if (empty($rawUser)) {
            return $next($request);
        }

        $emailHeader = config('pterodactyl.auth.header.email_header', 'Remote-Email');
        $rawEmail = $this->getHeaderValue($request, $emailHeader);

        $username = $this->sanitizeUsername($rawUser);
        $email = $this->resolveEmail($rawEmail, $rawUser, $username);

        $currentUser = $request->user();
        if ($currentUser) {
            if (
                mb_strtolower($currentUser->username) === mb_strtolower($username)
                || (!empty($email) && mb_strtolower($currentUser->email) === mb_strtolower($email))
            ) {
                return $next($request);
            }

            // A different user identity was supplied in the proxy headers.
            $this->auth->guard()->logout();
            if ($request->hasSession()) {
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }
        }

        $user = $this->findUser($username, $email);

        if (!$user && config('pterodactyl.auth.header.create_user', true)) {
            $user = $this->createUser($request, $username, $email);
        }

        if ($user) {
            $this->auth->guard()->login($user, true);
            if ($request->hasSession()) {
                $request->session()->regenerate();
            }
            $request->setUserResolver(fn () => $user);

            Event::dispatch(new DirectLogin($user, true));
        }

        return $next($request);
    }

    /**
     * Determines whether the incoming request originated from a trusted proxy.
     */
    protected function isTrustedRequest(Request $request): bool
    {
        $trustedProxies = config('pterodactyl.auth.header.trusted_proxies');

        if (!empty($trustedProxies)) {
            if ($trustedProxies === '*' || $trustedProxies === '**' || (is_array($trustedProxies) && (in_array('*', $trustedProxies, true) || in_array('**', $trustedProxies, true)))) {
                return true;
            }

            $proxies = is_array($trustedProxies)
                ? $trustedProxies
                : array_map('trim', explode(',', $trustedProxies));

            $clientIp = $request->server('REMOTE_ADDR') ?? $request->ip();

            return IpUtils::checkIp($clientIp, $proxies);
        }

        $globalProxies = config('trustedproxy.proxies');
        if (!empty($globalProxies) && $globalProxies !== ['']) {
            return $request->isFromTrustedProxy();
        }

        return true;
    }

    /**
     * Look up a header value, falling back to server environment variables if necessary.
     */
    protected function getHeaderValue(Request $request, ?string $headerName): ?string
    {
        if (empty($headerName)) {
            return null;
        }

        $value = $request->header($headerName);
        if (is_string($value) && trim($value) !== '') {
            return trim($value);
        }

        if (str_starts_with(strtoupper($headerName), 'HTTP_')) {
            $normalized = str_replace('_', '-', substr($headerName, 5));
            $value = $request->header($normalized);
            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        $serverKey = strtoupper(str_replace('-', '_', $headerName));
        $serverValue = $request->server($serverKey) ?: $request->server('HTTP_' . $serverKey);
        if (is_string($serverValue) && trim($serverValue) !== '') {
            return trim($serverValue);
        }

        $serverValue = $request->server('REDIRECT_' . $serverKey) ?: $request->server('REDIRECT_HTTP_' . $serverKey);
        if (is_string($serverValue) && trim($serverValue) !== '') {
            return trim($serverValue);
        }

        return null;
    }

    /**
     * Sanitize a username to adhere to Pterodactyl's username requirements.
     */
    protected function sanitizeUsername(string $rawUser): string
    {
        $username = trim($rawUser);

        if (str_contains($username, '@')) {
            $username = strtok($username, '@') ?: $username;
        }

        if (str_contains($username, '\\')) {
            $username = substr($username, strrpos($username, '\\') + 1);
        }

        $sanitized = preg_replace('/[^a-zA-Z0-9_.-]/', '', $username);
        $sanitized = trim($sanitized ?? '', '_.-');
        $sanitized = mb_strtolower($sanitized);
        $sanitized = substr($sanitized, 0, 191);
        $sanitized = trim($sanitized, '_.-');

        if (strlen($sanitized) < 3) {
            $sanitized = str_pad($sanitized, 3, '0');
        }

        return $sanitized;
    }

    /**
     * Resolves the email address from provided header values or raw username.
     */
    protected function resolveEmail(?string $rawEmail, string $rawUser, string $username): ?string
    {
        if (!empty($rawEmail) && filter_var(trim($rawEmail), FILTER_VALIDATE_EMAIL)) {
            return trim($rawEmail);
        }

        if (filter_var(trim($rawUser), FILTER_VALIDATE_EMAIL)) {
            return trim($rawUser);
        }

        return null;
    }

    /**
     * Locate an existing user by username or email.
     */
    protected function findUser(string $username, ?string $email): ?User
    {
        try {
            /** @var User $user */
            $user = $this->userRepository->findFirstWhere(['username' => $username]);

            return $user;
        } catch (RecordNotFoundException) {
            if (!empty($email)) {
                try {
                    /** @var User $user */
                    $user = $this->userRepository->findFirstWhere(['email' => $email]);

                    return $user;
                } catch (RecordNotFoundException) {
                    return null;
                }
            }
        }

        return null;
    }

    /**
     * Create a new user automatically using the provided credentials.
     */
    protected function createUser(Request $request, string $username, ?string $email): ?User
    {
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $host = parse_url(config('app.url', 'http://localhost'), PHP_URL_HOST);
            $domain = (!empty($host) && !in_array($host, ['localhost', '127.0.0.1'])) ? $host : 'example.com';
            $email = $username . '@' . $domain;
        }

        $firstName = ucfirst($username);
        $lastName = 'User';

        $nameHeader = config('pterodactyl.auth.header.name_header', 'Remote-Name');
        $rawName = $this->getHeaderValue($request, $nameHeader);
        if (!empty($rawName)) {
            $parts = preg_split('/\s+/', trim($rawName), 2);
            if (!empty($parts[0])) {
                $firstName = $parts[0];
                $lastName = $parts[1] ?? 'User';
            }
        }

        $firstName = mb_substr(trim($firstName), 0, 191);
        $lastName = mb_substr(trim($lastName), 0, 191);
        if (empty($firstName)) {
            $firstName = ucfirst($username);
        }
        if (empty($lastName)) {
            $lastName = 'User';
        }

        try {
            return $this->userCreationService->handle([
                'email' => $email,
                'username' => $username,
                'name_first' => $firstName,
                'name_last' => $lastName,
                'root_admin' => false,
            ]);
        } catch (\Throwable $e) {
            $user = $this->findUser($username, $email);
            if ($user) {
                return $user;
            }

            Log::error('Failed to automatically create user via header authentication', [
                'username' => $username,
                'email' => $email,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
