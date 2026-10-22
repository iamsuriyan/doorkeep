<?php
/**
 * Plugin Name:       doorkeep
 * Plugin URI:        https://github.com/iamsuriyan/doorkeep
 * Description:       Self-hosted, privacy-preserving bot protection for login, registration, password reset, comments and WooCommerce checkout. No third-party scripts.
 * Version:           0.2.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * License:           Apache-2.0
 * Text Domain:       doorkeep
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Doorkeep_Plugin
{
    const OPT = 'doorkeep_settings';
    const META = '_doorkeep_event_id';
    private static ?array $last = null; // last verify result in this request

    public static function init(): void
    {
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_init', [self::class, 'register_settings']);
        if (!self::configured()) {
            return;
        }
        $o = self::opts();
        // wp-login.php serves login, registration and lost password: load the
        // snippet there if any of them is protected.
        if ($o['login'] || $o['register'] || $o['lostpassword']) {
            add_action('login_enqueue_scripts', [self::class, 'enqueue']);
        }
        if ($o['login']) {
            add_action('login_form', [self::class, 'placeholder_login']);
            add_filter('authenticate', [self::class, 'check_login'], 30, 3);
        }
        if ($o['register']) {
            add_action('register_form', [self::class, 'placeholder_register']);
            add_filter('registration_errors', [self::class, 'check_register'], 10, 3);
        }
        if ($o['lostpassword']) {
            add_action('lostpassword_form', [self::class, 'placeholder_lostpassword']);
            add_action('lostpassword_post', [self::class, 'check_lostpassword'], 10, 1);
        }
        if ($o['comments']) {
            add_action('wp_enqueue_scripts', [self::class, 'enqueue_front']);
            add_action('comment_form_after_fields', [self::class, 'placeholder_comment']);
            add_action('comment_form_logged_in_after', [self::class, 'placeholder_comment']);
            add_filter('preprocess_comment', [self::class, 'check_comment']);
            add_action('comment_post', [self::class, 'remember_event']);
            add_action('transition_comment_status', [self::class, 'report_spam'], 10, 3);
        }
        if ($o['woocommerce']) {
            add_action('wp_enqueue_scripts', [self::class, 'enqueue_front']);
            add_action('woocommerce_review_order_before_submit', [self::class, 'placeholder_checkout']);
            add_action('woocommerce_checkout_process', [self::class, 'check_checkout']);
            // Block checkout posts to the Store API instead of submitting a form.
            add_action('woocommerce_store_api_checkout_update_order_from_request', [self::class, 'check_block_checkout'], 10, 2);
            add_action('wp_enqueue_scripts', [self::class, 'enqueue_block_checkout'], 20);
        }
    }

    // ---------------- settings ----------------

    public static function defaults(): array
    {
        return [
            'public_url' => '', 'verify_url' => '', 'site_key' => '', 'secret' => '', 'fail_open' => 0, 'trusted_proxies' => '',
            'login' => 1, 'register' => 1, 'lostpassword' => 1, 'comments' => 1, 'woocommerce' => 0, 'compat' => '',
        ];
    }

    public static function opts(): array
    {
        $o = get_option(self::OPT, []);
        return array_merge(self::defaults(), is_array($o) ? $o : []);
    }

    private static function configured(): bool
    {
        $o = self::opts();
        return $o['public_url'] !== '' && $o['site_key'] !== '' && $o['secret'] !== '';
    }

    public static function menu(): void
    {
        add_options_page('doorkeep', 'doorkeep', 'manage_options', 'doorkeep', [self::class, 'page']);
    }

    public static function register_settings(): void
    {
        register_setting('doorkeep', self::OPT, ['sanitize_callback' => [self::class, 'sanitize']]);
    }

    public static function sanitize($in): array
    {
        $in = is_array($in) ? $in : [];
        $d = self::defaults();
        $out = [];
        foreach (['public_url', 'verify_url'] as $k) {
            $out[$k] = esc_url_raw(trim((string)($in[$k] ?? '')), ['http', 'https']);
        }
        foreach (['site_key', 'secret'] as $k) {
            $out[$k] = preg_replace('/[^A-Za-z0-9_\-]/', '', (string)($in[$k] ?? ''));
        }
        // Keep the stored secret when the field is left blank.
        if ($out['secret'] === '') {
            $out['secret'] = self::opts()['secret'];
        }
        foreach (['fail_open', 'login', 'register', 'lostpassword', 'comments', 'woocommerce'] as $k) {
            $out[$k] = empty($in[$k]) ? 0 : 1;
        }
        $compat = (string)($in['compat'] ?? '');
        $out['compat'] = in_array($compat, ['turnstile', 'recaptcha'], true) ? $compat : '';
        $proxies = [];
        foreach (preg_split('/[\s,]+/', (string)($in['trusted_proxies'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) as $p) {
            if (self::parse_cidr($p) !== null) {
                $proxies[] = $p;
            }
        }
        $out['trusted_proxies'] = implode(', ', $proxies);
        return array_merge($d, $out);
    }

    public static function page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $o = self::opts();
        $checks = ['login' => 'Login', 'register' => 'Registration', 'lostpassword' => 'Lost password', 'comments' => 'Comments', 'woocommerce' => 'WooCommerce checkout'];
        ?>
        <div class="wrap">
            <h1>doorkeep</h1>
            <p>Self-hosted bot protection. Create a site with <code>doorkeep site create --origin <?php echo esc_html(home_url()); ?></code> and paste its keys here.</p>
            <form method="post" action="options.php">
                <?php settings_fields('doorkeep'); ?>
                <table class="form-table" role="presentation">
                    <tr><th scope="row"><label for="dk-public">doorkeep URL (browser)</label></th>
                        <td><input id="dk-public" class="regular-text" name="<?php echo self::OPT; ?>[public_url]" value="<?php echo esc_attr($o['public_url']); ?>" placeholder="https://dk.example.com or <?php echo esc_attr(home_url('/_dk')); ?>">
                        <p class="description">Where browsers load the snippet. Same-origin <code>/_dk</code> via your web server is best.</p></td></tr>
                    <tr><th scope="row"><label for="dk-verify">doorkeep URL (server)</label></th>
                        <td><input id="dk-verify" class="regular-text" name="<?php echo self::OPT; ?>[verify_url]" value="<?php echo esc_attr($o['verify_url']); ?>" placeholder="http://127.0.0.1:8080">
                        <p class="description">Where WordPress verifies tokens. Defaults to the browser URL.</p></td></tr>
                    <tr><th scope="row"><label for="dk-key">Site key</label></th>
                        <td><input id="dk-key" class="regular-text code" name="<?php echo self::OPT; ?>[site_key]" value="<?php echo esc_attr($o['site_key']); ?>"></td></tr>
                    <tr><th scope="row"><label for="dk-secret">Secret</label></th>
                        <td><input id="dk-secret" type="password" class="regular-text code" name="<?php echo self::OPT; ?>[secret]" value="" placeholder="<?php echo $o['secret'] ? esc_attr__('(saved, leave blank to keep)', 'doorkeep') : ''; ?>" autocomplete="off"></td></tr>
                    <tr><th scope="row">Protect</th><td><fieldset>
                        <?php foreach ($checks as $k => $label) : ?>
                            <label><input type="checkbox" name="<?php echo self::OPT; ?>[<?php echo $k; ?>]" value="1" <?php checked($o[$k], 1); ?>> <?php echo esc_html($label); ?></label><br>
                        <?php endforeach; ?>
                    </fieldset></td></tr>
                    <tr><th scope="row">If doorkeep is unreachable</th><td><fieldset>
                        <label><input type="radio" name="<?php echo self::OPT; ?>[fail_open]" value="0" <?php checked($o['fail_open'], 0); ?>> Refuse the request (safer)</label><br>
                        <label><input type="radio" name="<?php echo self::OPT; ?>[fail_open]" value="1" <?php checked($o['fail_open'], 1); ?>> Let it through</label>
                    </fieldset></td></tr>
                    <tr><th scope="row"><label for="dk-proxies">Trusted proxies</label></th>
                        <td><input id="dk-proxies" class="regular-text code" name="<?php echo self::OPT; ?>[trusted_proxies]" value="<?php echo esc_attr($o['trusted_proxies']); ?>" placeholder="127.0.0.1, 10.0.0.0/8">
                        <p class="description">Addresses or CIDR ranges of reverse proxies or a CDN in front of WordPress. Their <code>X-Forwarded-For</code> is used to find the visitor's address; leave empty if visitors connect directly.</p></td></tr>
                    <tr><th scope="row"><label for="dk-compat">Field-name compatibility</label></th><td>
                        <select id="dk-compat" name="<?php echo self::OPT; ?>[compat]">
                            <option value="" <?php selected($o['compat'], ''); ?>>None</option>
                            <option value="turnstile" <?php selected($o['compat'], 'turnstile'); ?>>Turnstile (cf-turnstile-response)</option>
                            <option value="recaptcha" <?php selected($o['compat'], 'recaptcha'); ?>>reCAPTCHA (g-recaptcha-response)</option>
                        </select></td></tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    // ---------------- front end ----------------

    public static function enqueue(): void
    {
        $o = self::opts();
        $src = rtrim($o['public_url'], '/') . '/v1/dk.js';
        wp_enqueue_script('doorkeep', $src, [], null, ['strategy' => 'defer']);
    }

    public static function enqueue_front(): void
    {
        $o = self::opts();
        $needs = ($o['comments'] && is_singular() && comments_open()) || ($o['woocommerce'] && function_exists('is_checkout') && is_checkout());
        if ($needs) {
            self::enqueue();
        }
    }

    // Data attributes are added to the script tag WordPress prints.
    public static function script_attrs(string $tag, string $handle): string
    {
        if ($handle !== 'doorkeep') {
            return $tag;
        }
        $o = self::opts();
        $attrs = ' data-sitekey="' . esc_attr($o['site_key']) . '" data-endpoint="' . esc_attr(rtrim($o['public_url'], '/')) . '"';
        if ($o['compat']) {
            $attrs .= ' data-compat="' . esc_attr($o['compat']) . '"';
        }
        return str_replace(' src=', $attrs . ' src=', $tag);
    }

    private static function placeholder(string $action): void
    {
        echo '<div class="doorkeep" data-action="' . esc_attr($action) . '"></div>';
    }
    public static function placeholder_login(): void { self::placeholder('login'); }
    public static function placeholder_register(): void { self::placeholder('register'); }
    public static function placeholder_lostpassword(): void { self::placeholder('lostpassword'); }
    public static function placeholder_comment(): void { self::placeholder('comment'); }
    public static function placeholder_checkout(): void { self::placeholder('checkout'); }

    // ---------------- verification ----------------

    /** @return array{ok: bool, result: array} */
    private static function verify(string $action, ?string $token = null): array
    {
        $o = self::opts();
        if ($token === null) {
            $token = isset($_POST['dk-response']) ? sanitize_text_field(wp_unslash($_POST['dk-response'])) : '';
        }
        if ($token === '') {
            return ['ok' => false, 'result' => ['error-codes' => ['missing-input-response']]];
        }
        $endpoint = rtrim($o['verify_url'] !== '' ? $o['verify_url'] : $o['public_url'], '/');
        $res = wp_remote_post($endpoint . '/v1/siteverify', [
            'timeout' => 3,
            'body' => [
                'secret' => $o['secret'], 'response' => $token, 'expected_action' => $action,
                'remoteip' => self::client_ip(),
            ],
        ]);
        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) >= 500) {
            return ['ok' => (bool)$o['fail_open'], 'result' => ['error-codes' => ['unavailable']]];
        }
        $j = json_decode(wp_remote_retrieve_body($res), true);
        if (!is_array($j)) {
            return ['ok' => (bool)$o['fail_open'], 'result' => ['error-codes' => ['bad-response']]];
        }
        self::$last = $j;
        return ['ok' => !empty($j['success']), 'result' => $j];
    }

    /**
     * The visitor's address: REMOTE_ADDR, or behind configured trusted
     * proxies the rightmost X-Forwarded-For hop that is not a trusted proxy
     * (hops further left are whatever the client claimed).
     */
    public static function client_ip(): string
    {
        $addr = isset($_SERVER['REMOTE_ADDR']) ? trim((string)wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        $trusted = array_filter(array_map([self::class, 'parse_cidr'], preg_split('/[\s,]+/', self::opts()['trusted_proxies'], -1, PREG_SPLIT_NO_EMPTY)));
        if (!$trusted || !self::in_any($addr, $trusted)) {
            return filter_var($addr, FILTER_VALIDATE_IP) ? $addr : '';
        }
        $xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? (string)wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']) : '';
        foreach (array_reverse(array_map('trim', explode(',', $xff))) as $hop) {
            if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                break;
            }
            $addr = $hop;
            if (!self::in_any($hop, $trusted)) {
                break;
            }
        }
        return $addr;
    }

    /** @return array{0: string, 1: int}|null packed network and prefix length */
    public static function parse_cidr(string $s): ?array
    {
        [$ip, $bits] = array_pad(explode('/', trim($s), 2), 2, null);
        $packed = @inet_pton((string)$ip);
        if ($packed === false) {
            return null;
        }
        $max = strlen($packed) * 8;
        $bits = $bits === null ? $max : (ctype_digit($bits) ? (int)$bits : -1);
        return ($bits < 0 || $bits > $max) ? null : [$packed, $bits];
    }

    private static function in_any(string $ip, array $nets): bool
    {
        $p = @inet_pton($ip);
        if ($p === false) {
            return false;
        }
        foreach ($nets as [$net, $bits]) {
            if (strlen($net) !== strlen($p)) {
                continue;
            }
            $full = intdiv($bits, 8);
            $rest = $bits % 8;
            if (substr($p, 0, $full) !== substr($net, 0, $full)) {
                continue;
            }
            if ($rest === 0 || ((ord($p[$full]) ^ ord($net[$full])) & (0xFF << (8 - $rest)) & 0xFF) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function message(): string
    {
        return __('<strong>Error:</strong> we could not verify this request. Please try again.', 'doorkeep');
    }

    public static function check_login($user, $username, $password)
    {
        if (empty($_POST) || $username === '' || is_wp_error($user) && $user->get_error_code() === 'empty_username') {
            return $user;
        }
        $v = self::verify('login');
        return $v['ok'] ? $user : new WP_Error('doorkeep_failed', self::message());
    }

    public static function check_register($errors, $login, $email)
    {
        $v = self::verify('register');
        if (!$v['ok']) {
            $errors->add('doorkeep_failed', self::message());
        }
        return $errors;
    }

    public static function check_lostpassword($errors): void
    {
        $v = self::verify('lostpassword');
        if (!$v['ok'] && $errors instanceof WP_Error) {
            $errors->add('doorkeep_failed', self::message());
        }
    }

    public static function check_comment(array $data): array
    {
        // Trackbacks and pingbacks have no browser to check.
        if (in_array($data['comment_type'] ?? '', ['pingback', 'trackback'], true)) {
            return $data;
        }
        $v = self::verify('comment');
        if (!$v['ok']) {
            wp_die(self::message(), __('Comment not posted', 'doorkeep'), ['response' => 403, 'back_link' => true]);
        }
        return $data;
    }

    public static function remember_event(int $comment_id): void
    {
        if (!empty(self::$last['doorkeep']['event_id'])) {
            add_comment_meta($comment_id, self::META, sanitize_text_field(self::$last['doorkeep']['event_id']), true);
        }
    }

    /** Marking a comment as spam teaches the site's model it was a bot. */
    public static function report_spam($new, $old, $comment): void
    {
        if ($new !== 'spam' && !($old === 'spam' && $new === 'approved')) {
            return;
        }
        $event = get_comment_meta($comment->comment_ID, self::META, true);
        if (!$event) {
            return;
        }
        $o = self::opts();
        $endpoint = rtrim($o['verify_url'] !== '' ? $o['verify_url'] : $o['public_url'], '/');
        wp_remote_post($endpoint . '/v1/report', ['timeout' => 3, 'blocking' => false, 'body' => [
            'secret' => $o['secret'], 'event_id' => $event, 'label' => $new === 'spam' ? 'bot' : 'human',
        ]]);
    }

    public static function check_checkout(): void
    {
        $v = self::verify('checkout');
        if (!$v['ok'] && function_exists('wc_add_notice')) {
            wc_add_notice(wp_strip_all_tags(self::message()), 'error');
        }
    }

    /**
     * Block checkout: the token arrives as an X-Doorkeep-Response header on
     * the Store API checkout request (added by the apiFetch middleware in
     * enqueue_block_checkout). Throwing a RouteException rejects the order.
     */
    public static function check_block_checkout($order, $request): void
    {
        $token = sanitize_text_field((string)$request->get_header('x-doorkeep-response'));
        $v = self::verify('checkout', $token);
        if (!$v['ok']) {
            throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException('doorkeep_failed', wp_strip_all_tags(self::message()), 403);
        }
    }

    /**
     * On the block checkout page, add the apiFetch middleware (block-checkout.js)
     * that attaches a fresh token to the Store API checkout request.
     */
    public static function enqueue_block_checkout(): void
    {
        if (!function_exists('is_checkout') || !is_checkout() || !wp_script_is('doorkeep', 'enqueued')) {
            return;
        }
        wp_enqueue_script('doorkeep-block-checkout', plugins_url('block-checkout.js', __FILE__), ['wp-api-fetch', 'doorkeep'], '0.2.0', ['in_footer' => true]);
    }
}

add_filter('script_loader_tag', [Doorkeep_Plugin::class, 'script_attrs'], 10, 2);
add_action('plugins_loaded', [Doorkeep_Plugin::class, 'init']);

if (defined('WP_CLI') && WP_CLI) {
    /**
     * Checks that WordPress can reach doorkeep.
     *
     * ## EXAMPLES
     *     wp doorkeep test
     */
    WP_CLI::add_command('doorkeep test', function () {
        $o = Doorkeep_Plugin::opts();
        $endpoint = rtrim($o['verify_url'] !== '' ? $o['verify_url'] : $o['public_url'], '/');
        if ($endpoint === '') {
            WP_CLI::error('Not configured: set the doorkeep URL in Settings → doorkeep.');
        }
        $r = wp_remote_get($endpoint . '/healthz', ['timeout' => 3]);
        if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) {
            WP_CLI::error('Cannot reach ' . $endpoint . '/healthz');
        }
        $v = wp_remote_post($endpoint . '/v1/siteverify', ['timeout' => 3, 'body' => ['secret' => $o['secret'], 'response' => 'probe']]);
        $j = json_decode(wp_remote_retrieve_body($v), true);
        if (in_array('invalid-input-secret', $j['error-codes'] ?? [], true)) {
            WP_CLI::error('doorkeep is reachable but the secret is wrong.');
        }
        WP_CLI::success('doorkeep is reachable and the secret is accepted.');
    });
}
