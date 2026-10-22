<?php
// Router for `php -S`: a stand-in doorkeep for the Verifier tests.
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
parse_str(file_get_contents('php://input'), $form);
file_put_contents(sys_get_temp_dir() . '/dk_last_form.json', json_encode(['path' => $path, 'form' => $form]));
header('Content-Type: application/json');
switch ($path) {
    case '/ok/v1/siteverify':
        echo json_encode(['success' => true, 'error-codes' => [], 'doorkeep' => ['risk' => 3, 'outcome' => 'allow']]);
        break;
    case '/dup/v1/siteverify':
        echo json_encode(['success' => false, 'error-codes' => ['timeout-or-duplicate']]);
        break;
    case '/down/v1/siteverify':
        http_response_code(503);
        echo '{}';
        break;
    case '/html/v1/siteverify':
        http_response_code(404);
        header('Content-Type: text/html');
        echo '<html>not found</html>';
        break;
    case '/ok/v1/report':
        echo json_encode(['success' => ($form['label'] ?? '') === 'bot', 'error-codes' => []]);
        break;
    default:
        http_response_code(404);
}
