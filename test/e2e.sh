#!/bin/bash
# End-to-end test: daemon + a Node "phone" holding the keys + a throwaway ssh-agent as the
# upstream agent. Run: bash test/e2e.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd); BIN=$ROOT/target/release/pocket-agent
T=${TMPDIR%/}/pocket-agent-test; rm -rf "$T"; mkdir -p "$T"; cd "$T"; echo "workdir $T"
fail=0; check() { if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3 (got '$1', want '$2')"; fail=1; fi; }
cleanup() { kill $DPID $APID $PPID2 2>/dev/null; }; trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -C 'in-upstream' -f keyA
ssh-agent -a "$T/up.sock" -D >/dev/null 2>&1 & APID=$!; sleep 0.5
SSH_AUTH_SOCK=$T/up.sock ssh-add -q keyA; rm keyA
ssh-keygen -q -t ed25519 -N '' -C 'phone-ed25519' -f keyB
ssh-keygen -q -t ecdsa -b 256 -N '' -C 'phone-ecdsa' -f keyC
ssh-keygen -q -t rsa -b 2048 -N '' -C 'phone-rsa' -f keyD

cat > cfg.json <<EOC
{"agent_socket":"$T/agent.sock","upstream_socket":"$T/up.sock","state_file":"$T/state.json","http_bind":"127.0.0.1","http_port":8421,"tls":false,"allow_local_api":true,"public_url":"http://127.0.0.1:8421","sign_timeout_seconds":5}
EOC
"$BIN" --config cfg.json serve > daemon.log 2>&1 & DPID=$!; sleep 1
export SSH_AUTH_SOCK=$T/agent.sock
node "$ROOT/test/phone.mjs" http://127.0.0.1:8421 deadbeef0001 1 keyB keyC keyD > phone.log 2>&1 & PPID2=$!; sleep 1.5
mv keyB keyB.private; mv keyC keyC.private; mv keyD keyD.private   # ssh-keygen must go through the agent

check "$(ssh-add -l | wc -l | tr -d ' ')" 4 "agent lists 3 phone keys + the upstream key"
check "$(ssh-add -l | grep -c 'phone-ed25519\|phone-ecdsa\|phone-rsa')" 3 "phone keys carry their names"
echo hello > msg
for k in B:phone-ed25519 C:phone-ecdsa D:phone-rsa; do
  f=${k%%:*}; n=${k#*:}; cp msg m$f
  ssh-keygen -q -Y sign -f key$f.pub -n test m$f 2>/dev/null; check $? 0 "sign with $n via phone"
  awk -v n=$n '{print n" "$1" "$2}' key$f.pub > allowed$f
  ssh-keygen -Y verify -f allowed$f -I $n -n test -s m$f.sig < m$f >/dev/null 2>&1; check $? 0 "signature by $n verifies"
done
ssh-add -L | grep in-upstream > keyA.pub; cp msg mA
ssh-keygen -q -Y sign -f keyA.pub -n test mA 2>/dev/null; check $? 0 "upstream key still signs via fallback"
grep -q 'proc=ssh-keygen' phone.log && echo "ok   phone saw the requesting process" || { echo "FAIL process info"; fail=1; }

echo "--- deny and timeout"
kill $PPID2; node "$ROOT/test/phone.mjs" http://127.0.0.1:8421 deadbeef0001 0 keyB.private > phone2.log 2>&1 & PPID2=$!; sleep 1.5
cp msg mX; ssh-keygen -q -Y sign -f keyB.pub -n test mX 2>/dev/null; check $? 255 "denied by phone → ssh-keygen fails"
kill $PPID2; sleep 0.3
cp msg mY; SECONDS=0; ssh-keygen -q -Y sign -f keyB.pub -n test mY 2>/dev/null; rc=$?; check $rc 255 "no phone → fails after timeout (${SECONDS}s)"
check "$(python3 -c 'import json; print(len(json.load(open("state.json"))["devices"][0]["keys"]))')" 1 "device state persisted (1 key after re-register)"
check "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8421/)" 200 "app served"
check "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8421/manifest.webmanifest)" 200 "manifest served"
check "$(curl -s http://127.0.0.1:8421/api/state | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["upstream"][0]["name"], d["devices"][0]["name"], len(d["vapid_public"])>80)')" "in-upstream node-phone True" "state endpoint"
echo "--- daemon log:"; cat daemon.log
[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME FAILED"; exit 1; }
