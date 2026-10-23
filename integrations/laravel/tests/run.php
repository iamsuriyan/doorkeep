<?php
// Plain-PHP tests with minimal Laravel stubs: php integrations/laravel/tests/run.php
declare(strict_types=1);

namespace Illuminate\Contracts\Validation {
    interface ValidationRule { public function validate(string $attribute, mixed $value, \Closure $fail): void; }
}

namespace {
    require __DIR__ . '/../../php/src/Verifier.php';
    require __DIR__ . '/../../php/src/UnavailableException.php';
    require __DIR__ . '/../src/Rules/Doorkeep.php';
    require __DIR__ . '/../src/Http/Middleware/VerifyDoorkeep.php';

    class HttpAbort extends \RuntimeException {}
    function abort(int $code, string $msg = ''): never { throw new HttpAbort($msg, $code); }

    $port = 18600 + random_int(0, 300);
    $srv = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/../../php/tests/fake_doorkeep.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p);
    register_shutdown_function(fn () => proc_terminate($srv));
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) usleep(100_000);
    $base = "http://127.0.0.1:$port";
    $failures = 0;
    function check(string $n, bool $ok): void { global $failures; echo ($ok ? 'ok   ' : 'FAIL ') . "$n\n"; $failures += $ok ? 0 : 1; }
    function last(): array { return json_decode((string) file_get_contents(sys_get_temp_dir() . '/dk_last_form.json'), true); }

    // Validation rule.
    $msg = null;
    $rule = new Doorkeep\Laravel\Rules\Doorkeep('signup', '203.0.113.5', new Doorkeep\Verifier("$base/ok", 's'));
    $rule->validate('dk-response', 'tok', function ($m) use (&$msg) { $msg = $m; });
    check('rule passes a valid token', $msg === null && $rule->result['success'] === true);
    check('rule sends action and client IP', last()['form']['expected_action'] === 'signup' && last()['form']['remoteip'] === '203.0.113.5');
    $msg = null;
    (new Doorkeep\Laravel\Rules\Doorkeep('signup', null, new Doorkeep\Verifier("$base/dup", 's')))->validate('dk-response', 't', function ($m) use (&$msg) { $msg = $m; });
    check('rule fails a rejected token', is_string($msg));
    $msg = null;
    (new Doorkeep\Laravel\Rules\Doorkeep('', null, new Doorkeep\Verifier("$base/down", 's')))->validate('dk-response', 't', function ($m) use (&$msg) { $msg = $m; });
    check('rule fails closed when doorkeep is down', is_string($msg));
    $msg = null;
    (new Doorkeep\Laravel\Rules\Doorkeep('', null, new Doorkeep\Verifier("$base/down", 's', failOpen: true)))->validate('dk-response', 't', function ($m) use (&$msg) { $msg = $m; });
    check('rule passes when doorkeep is down and fail_open is set', $msg === null);

    // Middleware.
    $req = new class {
        public array $in = [];
        public object $attributes;
        public function __construct() { $this->attributes = new class { public array $a = []; public function set($k, $v) { $this->a[$k] = $v; } }; }
        public function input($k, $d = null) { return $this->in[$k] ?? $d; }
        public function ip() { return '198.51.100.9'; }
    };
    $req->in['dk-response'] = 'tok';
    $ran = false;
    (new Doorkeep\Laravel\Http\Middleware\VerifyDoorkeep(new Doorkeep\Verifier("$base/ok", 's')))->handle($req, function () use (&$ran) { $ran = true; return 'ok'; }, 'signup');
    check('middleware lets a valid token through', $ran && $req->attributes->a['doorkeep']['success'] === true);
    try {
        (new Doorkeep\Laravel\Http\Middleware\VerifyDoorkeep(new Doorkeep\Verifier("$base/dup", 's')))->handle($req, fn () => 'ok', 'signup');
        check('middleware answers 403 for a rejected token', false);
    } catch (HttpAbort $e) {
        check('middleware answers 403 for a rejected token', $e->getCode() === 403);
    }
    try {
        (new Doorkeep\Laravel\Http\Middleware\VerifyDoorkeep(new Doorkeep\Verifier("$base/down", 's')))->handle($req, fn () => 'ok');
        check('middleware answers 503 when doorkeep is down', false);
    } catch (HttpAbort $e) {
        check('middleware answers 503 when doorkeep is down', $e->getCode() === 503);
    }
    exit($failures === 0 ? 0 : 1);
}
