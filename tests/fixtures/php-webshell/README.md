# http_phpcmd validation fixture

Test-only HTTP/PHP endpoint used by `TestConnectionAdapterRealPHPFixture` and the
Linux acceptance run. It implements the ARTEX `http_phpcmd` wire protocol so the
adapter is exercised against a real HTTP server and a real PHP process.

This is **not** a production component and is not shipped in any ARTEX build
path. Nothing here is imported by the Go server, the Dockerfile, or compose.

## Protocol

```
POST <base_url>            Content-Type: application/json
X-Shell-Key: <secret>      (X-Artex-Key is also accepted)

{"v":1,"id":"<request id>","action":"ping|info|exec","cmd":"...","nonce":"...","ts":N,
 "args":{"argv":["/bin/echo","artex-ok"],"cwd":"/tmp","timeout_ms":5000}}
```

Success (200 — the exchange ran, not that the command succeeded):

```json
{"v":1,"id":"...","ok":true,"action":"exec","exit_code":0,"timed_out":false,
 "truncated":false,"stdout_b64":"...","stderr_b64":"...","duration_ms":12}
```

Error: `{"ok":false,"error":{"code":"...","message":"..."}}`

Codes: `bad_json`, `bad_id`, `bad_argv`, `query_not_allowed` (400), `unauthorized`
(401), `denied` (403/405), `too_large` (413), `spawn_failed` (500), `disabled`
(501), `misconfigured` (503). `ping` returns `pong` plus `server_time`; `info`
returns `php_version`, `sapi`, `user`, `can_exec` and `disabled_functions`.

Timeouts are reported as HTTP 200 with `timed_out: true` and `exit_code: null`.

## Controls

- Key comes from `ARTEX_SHELL_KEY` or `ARTEX_SHELL_KEY_FILE`; it must be at least
  32 bytes and is compared with `hash_equals` over SHA-256 digests. Missing key
  fails closed with 503; a wrong key is 401 and is never echoed or logged.
- Credentials are header-only; any query string is rejected with 400.
- Body is limited to 16 KiB and `Content-Length` is required.
- `exec` uses `proc_open` with an argv array (no shell). `cmd` runs as
  `["/bin/sh","-lc",cmd]`. argv is 1–32 items, ≤512 B each, ≤4096 B total, no NUL.
- stdin is closed; the environment is fixed; `cwd` defaults to `/tmp`.
- Timeout defaults to 5000 ms, maximum 10000 ms, enforced with `stream_select`
  plus `SIGKILL` and a 1 s hard stop.
- Output is capped at 48 KiB per stream / 64 KiB total; excess is drained and
  discarded with `truncated: true`.
- No eval, no upload, no PTY, no state, no filesystem writes.

## Docker (Linux host)

```sh
cd tests/fixtures/php-webshell
export ARTEX_SHELL_KEY="$(openssl rand -hex 32)"
docker build -t artex/php-fixture:8.3 .
docker run -d --rm --name artex-php-fixture -p 127.0.0.1:18080:80 \
  -e ARTEX_SHELL_KEY="$ARTEX_SHELL_KEY" \
  --cap-drop ALL --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges --memory 256m --pids-limit 64 \
  artex/php-fixture:8.3
docker inspect -f '{{.State.Health.Status}}' artex-php-fixture
```

Loopback publish only. Stop it with `docker stop artex-php-fixture`.

## Smoke test

`smoke.sh` runs the protocol cases with curl and exits non-zero on any mismatch:

```sh
ARTEX_SHELL_KEY=... ./smoke.sh http://127.0.0.1:18080/index.php
```

## Running the Go acceptance test

On the Linux host, with the container up and PostgreSQL reachable:

```sh
ARTEX_PG_DSN=postgres://artex:artex@127.0.0.1:55433/artex_test?sslmode=disable \
ARTEX_TEST_PHP_URL=http://127.0.0.1:18080/index.php \
ARTEX_TEST_PHP_KEY="$ARTEX_SHELL_KEY" \
/tmp/server.test -test.run TestConnectionAdapterRealPHPFixture -test.v
```

## Recorded validation (2026-11-11, Linux host `yeziyun`)

```sh
docker build -t artex/php-fixture:8.3 .
docker run -d --rm --name artex-php-fixture -p 127.0.0.1:18080:80 -e ARTEX_SHELL_KEY="$KEY" ...
docker inspect -f '{{.State.Health.Status}}' artex-php-fixture   # healthy

ARTEX_SHELL_KEY=$(cat /tmp/phpfix.key) bash ./smoke.sh http://127.0.0.1:18080/index.php
ok   ping 200
ok   echo exit 0
ok   echo stdout b64
ok   exit 7
ok   sleep timeout
ok   wrong key 401
ok   query string 400
ok   oversized body 413

ARTEX_PG_DSN=postgres://artex:artex@127.0.0.1:55433/artex_test?sslmode=disable \
ARTEX_TEST_PHP_URL=http://127.0.0.1:18080/index.php \
ARTEX_TEST_PHP_KEY="$KEY" \
/tmp/testbin -test.run TestConnectionAdapterRealPHPFixture -test.v
--- PASS: TestConnectionAdapterRealPHPFixture (1.05s)
```
