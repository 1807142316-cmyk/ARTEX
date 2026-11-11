<?php
// Liveness probe for the fixture container. Reports only whether a key is
// configured; it never reveals the key itself.
declare(strict_types=1);
header('Content-Type: application/json');
header('Cache-Control: no-store');
$file = getenv('ARTEX_SHELL_KEY_FILE');
$direct = getenv('ARTEX_SHELL_KEY');
$configured = (is_string($file) && $file !== '' && is_readable($file) && trim((string) file_get_contents($file)) !== '')
    || (is_string($direct) && strlen(trim($direct)) >= 32);
http_response_code($configured ? 200 : 503);
echo json_encode(['ok' => $configured, 'service' => 'artex-php-fixture']);
