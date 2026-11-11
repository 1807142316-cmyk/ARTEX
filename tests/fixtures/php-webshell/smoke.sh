#!/usr/bin/env bash
# Protocol smoke test for the http_phpcmd fixture. Requires curl and jq-free
# parsing (grep). Exits non-zero on the first mismatch.
set -u

BASE="${1:-http://127.0.0.1:18080/index.php}"
KEY="${ARTEX_SHELL_KEY:?ARTEX_SHELL_KEY must be set}"
FAILED=0

call() { # call <id> <json-body> -> body, status appended on last line
  curl -sS -o /tmp/artex-smoke-body -w '%{http_code}' \
    -X POST "$BASE" -H 'Content-Type: application/json' -H "X-Shell-Key: $KEY" \
    --data-binary "$2"
}

check() { # check <label> <condition-result> <detail>
  if [ "$2" = "0" ]; then
    printf 'ok   %s\n' "$1"
  else
    printf 'FAIL %s — %s\n' "$1" "$3"
    FAILED=1
  fi
}

status=$(call ping '{"v":1,"id":"smoke-ping","action":"ping","nonce":"n","ts":1}')
grep -q '"ok":true' /tmp/artex-smoke-body; ping_ok=$?
check "ping 200" $(( status != 200 || ping_ok != 0 )) "status=$status body=$(cat /tmp/artex-smoke-body)"

status=$(call exec '{"v":1,"id":"smoke-echo","action":"exec","nonce":"n","ts":1,"args":{"argv":["/bin/echo","artex-ok"]}}')
grep -q '"exit_code":0' /tmp/artex-smoke-body; check "echo exit 0" $? "body=$(cat /tmp/artex-smoke-body)"
grep -q 'YXJ0ZXgtb2sK' /tmp/artex-smoke-body; check "echo stdout b64" $? "body=$(cat /tmp/artex-smoke-body)"

status=$(call exec '{"v":1,"id":"smoke-exit7","action":"exec","nonce":"n","ts":1,"args":{"argv":["/bin/sh","-c","exit 7"]}}')
grep -q '"exit_code":7' /tmp/artex-smoke-body; check "exit 7" $? "body=$(cat /tmp/artex-smoke-body)"

status=$(call exec '{"v":1,"id":"smoke-timeout","action":"exec","nonce":"n","ts":1,"args":{"argv":["/bin/sleep","30"],"timeout_ms":800}}')
grep -q '"timed_out":true' /tmp/artex-smoke-body; check "sleep timeout" $? "body=$(cat /tmp/artex-smoke-body)"

status=$(curl -sS -o /tmp/artex-smoke-body -w '%{http_code}' -X POST "$BASE" \
  -H 'Content-Type: application/json' -H 'X-Shell-Key: wrong-key-0000000000000000000000000000' \
  --data-binary '{"v":1,"id":"smoke-bad","action":"ping"}')
check "wrong key 401" $(( status != 401 )) "status=$status"

status=$(curl -sS -o /tmp/artex-smoke-body -w '%{http_code}' -X POST "$BASE?key=plaintext" \
  -H 'Content-Type: application/json' -H "X-Shell-Key: $KEY" \
  --data-binary '{"v":1,"id":"smoke-query","action":"ping"}')
check "query string 400" $(( status != 400 )) "status=$status"

head -c 40000 /dev/zero | tr '\0' 'x' > /tmp/artex-smoke-large
{ printf '{"v":1,"id":"smoke-large","action":"ping","pad":"'; cat /tmp/artex-smoke-large; printf '"}'; } > /tmp/artex-smoke-large.json
status=$(curl -sS -o /tmp/artex-smoke-body -w '%{http_code}' -X POST "$BASE" \
  -H 'Content-Type: application/json' -H "X-Shell-Key: $KEY" \
  --data-binary @/tmp/artex-smoke-large.json)
check "oversized body 413" $(( status != 413 )) "status=$status"

rm -f /tmp/artex-smoke-body /tmp/artex-smoke-large /tmp/artex-smoke-large.json
exit $FAILED
