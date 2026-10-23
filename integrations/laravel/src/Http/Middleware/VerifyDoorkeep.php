<?php

declare(strict_types=1);

namespace Doorkeep\Laravel\Http\Middleware;

use Closure;
use Doorkeep\UnavailableException;
use Doorkeep\Verifier;

/**
 * Route middleware: Route::post('/signup', ...)->middleware('doorkeep:signup');
 * The verify result is available as $request->attributes->get('doorkeep').
 */
final class VerifyDoorkeep
{
    public function __construct(private Verifier $verifier) {}

    public function handle($request, Closure $next, string $action = '')
    {
        try {
            $r = $this->verifier->verify((string) $request->input('dk-response', ''), array_filter(['action' => $action, 'remoteip' => $request->ip()]));
        } catch (UnavailableException) {
            abort(503, 'Verification is temporarily unavailable.');
        }
        $request->attributes->set('doorkeep', $r);
        if (empty($r['success'])) {
            abort(403, 'We could not verify this request. Please try again.');
        }
        return $next($request);
    }
}
