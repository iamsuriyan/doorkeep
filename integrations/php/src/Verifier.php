<?php
// doorkeep/verify: check a doorkeep token from a PHP backend.
//
//   $dk = new \Doorkeep\Verifier('https://dk.example.com', getenv('DOORKEEP_SECRET'));
//   $r = $dk->verify($_POST['dk-response'] ?? '', ['action' => 'signup', 'remoteip' => $_SERVER['REMOTE_ADDR']]);
//   if (!$r['success']) { http_response_code(403); exit('Please try again'); }

declare(strict_types=1);

namespace Doorkeep;

final class Verifier
{
    public function __construct(
        private string $endpoint,
        private string $secret,
        private bool $failOpen = false,
        private int $timeoutSeconds = 3,
    ) {
        $this->endpoint = rtrim($endpoint, '/');
    }

    /** @return array{success: bool, 'error-codes': string[], doorkeep?: array, failed_open?: bool} */
    public function verify(string $response, array $opts = []): array
    {
        if ($response === '') {
            return ['success' => false, 'error-codes' => ['missing-input-response']];
        }
        $form = ['secret' => $this->secret, 'response' => $response];
        if (!empty($opts['action'])) $form['expected_action'] = $opts['action'];
        if (!empty($opts['hostname'])) $form['expected_hostname'] = $opts['hostname'];
        if (!empty($opts['remoteip'])) $form['remoteip'] = $opts['remoteip'];
        $res = $this->post('/v1/siteverify', $form);
        if ($res === null) {
            if ($this->failOpen) return ['success' => true, 'error-codes' => [], 'failed_open' => true];
            throw new UnavailableException('doorkeep: verify unavailable');
        }
        return $res;
    }

    /** Label an event so the site's supervised model learns your ground truth. */
    public function report(string $eventId, bool $bot): bool
    {
        $res = $this->post('/v1/report', ['secret' => $this->secret, 'event_id' => $eventId, 'label' => $bot ? 'bot' : 'human']);
        return is_array($res) && !empty($res['success']);
    }

    private function post(string $path, array $form): ?array
    {
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($form),
            'timeout' => $this->timeoutSeconds,
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($this->endpoint . $path, false, $ctx);
        if ($body === false) return null;
        $status = 0;
        // PHP 8.4+ exposes the headers through a function; older versions
        // through the $http_response_header local.
        $headers = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
        foreach ($headers as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) $status = (int)$m[1];
        }
        if ($status >= 500) return null;
        $json = json_decode($body, true);
        return is_array($json) ? $json : null;
    }
}
