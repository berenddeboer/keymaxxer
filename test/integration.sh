#!/usr/bin/env bash
#
# End-to-end integration test for keymaxxer: drives the real CLI + agent daemon in
# an isolated $HOME, with no OS keychain and no GUI prompts (KEYMAXXER_APPROVE forces
# approval decisions headlessly). Exits non-zero if any assertion fails.
#
#   bash test/integration.sh

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/.." && pwd)
SH="bun $REPO/packages/cli/src/index.ts"
PASS="integ-pass-1234"

T=$(mktemp -d)
export HOME="$T"
unset KEYMAXXER_MASTER_KEY 2>/dev/null

OK=0
KO=0
pass() { echo "  ok   $1"; OK=$((OK + 1)); }
fail() { echo "  FAIL $1"; KO=$((KO + 1)); }
contains() { case "$2" in *"$3"*) pass "$1" ;; *) fail "$1 -- got: $(printf '%s' "$2" | tr '\n' ' ' | cut -c1-160)" ;; esac; }
absent()   { case "$2" in *"$3"*) fail "$1 -- unexpectedly contains '$3'" ;; *) pass "$1" ;; esac; }
mode()     { ls -ld "$1" | awk '{print substr($1,1,10)}'; }

cleanup() { KEYMAXXER_APPROVE=allow $SH lock >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT

echo "## lifecycle"
out=$(printf '%s\n%s\n' "$PASS" "$PASS" | KEYMAXXER_APPROVE=allow $SH init 2>&1)
contains "init creates the vault" "$out" "Vault created"
contains "init auto-unlocks the agent" "$out" "unlocked into the background agent"
contains "status reports unlocked" "$($SH status)" "Unlocked"

echo "## permissions"
contains "keymaxxer dir is 0700" "$(mode "$T/.keymaxxer")" "drwx------"
contains "agent socket is 0600" "$(mode "$T/.keymaxxer/agent.sock")" "srw-------"

echo "## secrets + metadata"
printf %s 'sk_test_abc'    | $SH set RO_KEY  --provider stripe --account acme --env dev  --access read-only  --tag pay >/dev/null
printf %s 'prod_secret_v1' | $SH set PROD_RW --provider stripe --account acme --env prod --access read-write          >/dev/null
contains "list shows structured attributes" "$($SH list)" "stripe · acme · dev · read-only"

echo "## injection + scrubbing"
contains "literal value is scrubbed (stdout)" "$($SH run --secrets RO_KEY -- 'echo v=$RO_KEY' 2>/dev/null)" "v=***"
contains "stderr is scrubbed too" "$($SH run --secrets RO_KEY -- 'echo e=$RO_KEY 1>&2' 2>&1 1>/dev/null)" "e=***"
contains "every occurrence is replaced" "$($SH run --secrets RO_KEY -- 'echo $RO_KEY-$RO_KEY-$RO_KEY' 2>/dev/null)" "***-***-***"
absent   "raw value never appears in output" "$($SH run --secrets RO_KEY -- 'echo $RO_KEY 1>&2; echo $RO_KEY' 2>&1)" "sk_test_abc"
absent   "transformed value is NOT scrubbed (documented limitation)" "$($SH run --secrets RO_KEY -- 'printf %s \"$RO_KEY\" | base64' 2>/dev/null)" "***"
if $SH run --secrets NOPE -- 'true' >/dev/null 2>&1; then fail "unknown secret should fail closed"; else pass "unknown secret fails closed"; fi

echo "## encryption at rest"
if head -c 16 "$T/.keymaxxer/vault.db" | grep -q "SQLite format 3"; then fail "vault must not be plaintext SQLite"; else pass "vault is encrypted at rest"; fi

echo "## multiprocess_wal (second opener while daemon holds the vault)"
conc=$(cd "$REPO" && HOME="$T" KEYMAXXER_TEST_PASS="$PASS" bun -e '
  import { SecretStore, loadMeta, deriveKey } from "keymaxxer-sdk";
  const v = process.env.HOME + "/.keymaxxer/vault.db";
  const m = loadMeta(v);
  const s = await SecretStore.open({ path: v, hexkey: deriveKey(process.env.KEYMAXXER_TEST_PASS, m.salt, m.scrypt) });
  process.stdout.write("CONC_OK:" + (await s.list()).length);
  await s.close();
' 2>&1)
contains "a second process can open the vault concurrently" "$conc" "CONC_OK:"

echo "## lock / locked / unlock"
$SH lock >/dev/null 2>&1
contains "status reports locked" "$($SH status)" "Locked"
contains "locked vault rejects operations" "$($SH list 2>&1)" "locked"
$SH lock >/dev/null 2>&1
contains "wrong passphrase is rejected" "$(printf '%s\n' 'definitely-wrong' | KEYMAXXER_APPROVE=allow $SH unlock 2>&1)" "wrong passphrase"
printf '%s\n' "$PASS" | KEYMAXXER_APPROVE=allow $SH unlock >/dev/null 2>&1
contains "correct passphrase unlocks" "$($SH status)" "Unlocked"

echo "## approval policy (deny)"
$SH lock >/dev/null 2>&1
printf '%s\n' "$PASS" | KEYMAXXER_APPROVE=deny $SH unlock >/dev/null 2>&1
contains "read-only/dev runs without approval" "$($SH run --secrets RO_KEY -- 'echo ro=$RO_KEY' 2>/dev/null)" "ro=***"
contains "read-write/prod is denied" "$($SH run --secrets PROD_RW -- 'echo $PROD_RW' 2>&1)" "was not approved"
contains "denial is recorded in the audit log" "$($SH audit --limit 10)" "DENIED"

echo "## approval policy (allow once)"
$SH lock >/dev/null 2>&1
printf '%s\n' "$PASS" | KEYMAXXER_APPROVE=allow $SH unlock >/dev/null 2>&1
contains "sensitive secret runs once approved" "$($SH run --secrets PROD_RW -- 'echo rw=$PROD_RW' 2>/dev/null)" "rw=***"
absent   "an 'allow once' approval does not persist" "$($SH status)" "Session-approved"

echo "## approval policy (allow for session)"
$SH lock >/dev/null 2>&1
printf '%s\n' "$PASS" | KEYMAXXER_APPROVE=session $SH unlock >/dev/null 2>&1
$SH run --secrets PROD_RW -- 'echo first=$PROD_RW' >/dev/null 2>&1   # first use grants the session
contains "secret is remembered for the session" "$($SH status)" "Session-approved (no re-prompt until lock): PROD_RW"
contains "session-approved secret runs again" "$($SH run --secrets PROD_RW -- 'echo again=$PROD_RW' 2>/dev/null)" "again=***"
$SH lock >/dev/null 2>&1
printf '%s\n' "$PASS" | KEYMAXXER_APPROVE=deny $SH unlock >/dev/null 2>&1
absent   "session approval is cleared after lock" "$($SH status)" "Session-approved"

echo
if [ "$KO" -eq 0 ]; then
  echo "ALL PASSED ($OK checks)"
  exit 0
else
  echo "$KO FAILED ($OK passed)"
  exit 1
fi
