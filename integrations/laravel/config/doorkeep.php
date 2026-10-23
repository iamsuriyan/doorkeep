<?php

return [
    // Where Laravel reaches doorkeep (server to server), and the site secret.
    'url' => env('DOORKEEP_URL', 'http://127.0.0.1:8080'),
    'secret' => env('DOORKEEP_SECRET'),
    // What to do when doorkeep is unreachable: false refuses the request.
    'fail_open' => (bool) env('DOORKEEP_FAIL_OPEN', false),
    'timeout' => (int) env('DOORKEEP_TIMEOUT', 3),
];
