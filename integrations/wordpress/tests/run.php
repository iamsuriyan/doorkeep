<?php
// Plain-PHP tests for the plugin's pure logic, with minimal WordPress stubs:
//   php integrations/wordpress/tests/run.php
// The full flow on a real WordPress is in testing/e2e/tests/wordpress.spec.ts.
declare(strict_types=1);

define('ABSPATH', __DIR__);
$GLOBALS['dk_opts'] = [];
$GLOBALS['dk_hooks'] = [];
function add_action($h, $cb, $p = 10, $a = 1) { $GLOBALS['dk_hooks'][] = $h; }
function add_filter($h, $cb, $p = 10, $a = 1) { $GLOBALS['dk_hooks'][] = $h; }
function get_option($k, $d = []) { return $GLOBALS['dk_opts']; }
function wp_unslash($v) { return $v; }
function esc_url_raw($u, $p = null) { return $u; }
function sanitize_text_field($v) { return trim((string)$v); }

require __DIR__ . '/../doorkeep/doorkeep.php';

$failures = 0;
function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? 'ok   ' : 'FAIL ') . $name . "\n";
    $failures += $ok ? 0 : 1;
}
function ip(string $remote, ?string $xff, string $trusted): string
{
    $GLOBALS['dk_opts'] = ['trusted_proxies' => $trusted];
    $_SERVER['REMOTE_ADDR'] = $remote;
    if ($xff === null) {
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    } else {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = $xff;
    }
    return Doorkeep_Plugin::client_ip();
}

check('direct visitor', ip('203.0.113.5', null, '') === '203.0.113.5');
check('XFF ignored without trusted proxies', ip('203.0.113.5', '6.6.6.6', '') === '203.0.113.5');
check('XFF ignored from an untrusted peer', ip('203.0.113.5', '6.6.6.6', '10.0.0.0/8') === '203.0.113.5');
check('behind one proxy', ip('10.0.0.2', '198.51.100.7', '10.0.0.0/8') === '198.51.100.7');
check('client-forged hop on the left is skipped', ip('10.0.0.2', '6.6.6.6, 198.51.100.7', '10.0.0.0/8') === '198.51.100.7');
check('chain of trusted proxies', ip('10.0.0.2', '198.51.100.7, 10.0.0.9', '10.0.0.0/8, 127.0.0.1') === '198.51.100.7');
check('garbage hop stops the walk', ip('10.0.0.2', '198.51.100.7, junk', '10.0.0.0/8') === '10.0.0.2');
check('IPv6 proxy and client', ip('fd00::1', '2001:db8::5', 'fd00::/8') === '2001:db8::5');

check('parse /24', Doorkeep_Plugin::parse_cidr('192.0.2.0/24') !== null);
check('parse bare address', Doorkeep_Plugin::parse_cidr('192.0.2.1')[1] === 32);
check('reject bad prefix', Doorkeep_Plugin::parse_cidr('192.0.2.0/33') === null && Doorkeep_Plugin::parse_cidr('nope') === null);

$s = Doorkeep_Plugin::sanitize(['trusted_proxies' => "10.0.0.0/8\nbogus, 127.0.0.1", 'public_url' => 'https://x', 'site_key' => 'dk_pk_a', 'secret' => 'dk_sk_b']);
check('sanitize keeps only valid proxies', $s['trusted_proxies'] === '10.0.0.0/8, 127.0.0.1');

// wp-login.php gets the snippet when only registration is protected.
$GLOBALS['dk_opts'] = ['public_url' => 'https://x', 'site_key' => 'k', 'secret' => 's', 'login' => 0, 'register' => 1, 'lostpassword' => 0, 'comments' => 0];
$GLOBALS['dk_hooks'] = [];
Doorkeep_Plugin::init();
check('register-only still enqueues on wp-login.php', in_array('login_enqueue_scripts', $GLOBALS['dk_hooks'], true));
check('register-only does not hook authenticate', !in_array('authenticate', $GLOBALS['dk_hooks'], true));

$GLOBALS['dk_opts']['woocommerce'] = 1;
$GLOBALS['dk_hooks'] = [];
Doorkeep_Plugin::init();
check('WooCommerce hooks block checkout', in_array('woocommerce_store_api_checkout_update_order_from_request', $GLOBALS['dk_hooks'], true));

exit($failures === 0 ? 0 : 1);
