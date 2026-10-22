<?php
// Plain-PHP tests (no PHPUnit): php tests/run.php
declare(strict_types=1);

require __DIR__ . '/../src/Verifier.php';
require __DIR__ . '/../src/UnavailableException.php';

use Doorkeep\UnavailableException;
use Doorkeep\Verifier;

$port = 18000 + random_int(0, 999);
$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fake_doorkeep.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
register_shutdown_function(fn () => proc_terminate($server));
for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(100_000);
}
$base = "http://127.0.0.1:$port";
$failures = 0;
function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
    $failures += $ok ? 0 : 1;
}
function last(): array
{
    return json_decode((string)file_get_contents(sys_get_temp_dir() . '/dk_last_form.json'), true);
}

$r = (new Verifier("$base/ok/", 'dk_sk_x'))->verify('tok', ['action' => 'signup', 'remoteip' => '203.0.113.5', 'hostname' => 'shop.example']);
$l = last();
check('verify success', $r['success'] === true && $r['doorkeep']['outcome'] === 'allow');
check('sends Turnstile-compatible form', $l['path'] === '/ok/v1/siteverify' && $l['form']['secret'] === 'dk_sk_x'
    && $l['form']['expected_action'] === 'signup' && $l['form']['remoteip'] === '203.0.113.5' && $l['form']['expected_hostname'] === 'shop.example');

check('missing token fails without a request', (new Verifier("$base/down", 's'))->verify('')['error-codes'] === ['missing-input-response']);
check('doorkeep failure passes through', (new Verifier("$base/dup", 's'))->verify('t')['error-codes'] === ['timeout-or-duplicate']);

foreach (['down' => '5xx', 'html' => 'non-JSON reply'] as $p => $what) {
    try {
        (new Verifier("$base/$p", 's'))->verify('t');
        check("$what fails closed", false);
    } catch (UnavailableException $e) {
        check("$what fails closed", true);
    }
    $open = (new Verifier("$base/$p", 's', failOpen: true))->verify('t');
    check("$what fails open when configured", $open['success'] === true && $open['failed_open'] === true);
}
try {
    (new Verifier('http://127.0.0.1:1', 's', timeoutSeconds: 1))->verify('t');
    check('unreachable fails closed', false);
} catch (UnavailableException $e) {
    check('unreachable fails closed', true);
}

check('report bot', (new Verifier("$base/ok", 's'))->report('evt_1', true) === true);
check('report sends label', last()['form']['label'] === 'bot' && last()['form']['event_id'] === 'evt_1');
check('report failure is false', (new Verifier("$base/ok", 's'))->report('evt_1', false) === false);

exit($failures === 0 ? 0 : 1);
