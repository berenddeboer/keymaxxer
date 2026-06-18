import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SecretStore } from "keymaxxer-sdk";
import { runGated } from "./src/client.js";

// runGated gates sensitive secrets behind approval, with a per-caller "approved"
// set that models "Allow for the session". KEYMAXXER_APPROVE forces the decision.

const dir = mkdtempSync(join(tmpdir(), "km-approve-"));
const path = join(dir, "vault.db");
const hexkey = "b1bbfda4f589dc9daaf004fe21111e00dc00c98237102f5c7002a5669fc76327";

let failures = 0;
function check(label: string, cond: boolean) {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) failures++;
}

try {
  const store = await SecretStore.open({ path, hexkey });
  await store.set("RW", "rw-value", { environment: "prod", access: "read-write" });
  await store.set("RO", "ro-value", { environment: "dev", access: "read-only" });

  // read-only is never gated, even with approval denied
  process.env.KEYMAXXER_APPROVE = "deny";
  const ro = await runGated(store, { command: "echo $RO", secrets: ["RO"] }, new Set());
  check("read-only runs without approval", ro.exitCode === 0 && ro.stdout.includes("***"));

  // sensitive + deny -> throws
  let denied = false;
  try {
    await runGated(store, { command: "true", secrets: ["RW"] }, new Set());
  } catch {
    denied = true;
  }
  check("sensitive denied when KEYMAXXER_APPROVE=deny", denied);

  // sensitive + session -> caches the name in the caller's approved set
  process.env.KEYMAXXER_APPROVE = "session";
  const approved = new Set<string>();
  await runGated(store, { command: "true", secrets: ["RW"] }, approved);
  check("'session' approval caches the secret", approved.has("RW"));

  // a cached secret bypasses approval entirely (deny is never consulted)
  process.env.KEYMAXXER_APPROVE = "deny";
  let ranCached = false;
  try {
    await runGated(store, { command: "true", secrets: ["RW"] }, approved);
    ranCached = true;
  } catch {
    /* should not happen */
  }
  check("cached approval bypasses re-prompt", ranCached);

  // 'once' does NOT cache — a fresh set stays empty
  process.env.KEYMAXXER_APPROVE = "once";
  const onceSet = new Set<string>();
  await runGated(store, { command: "true", secrets: ["RW"] }, onceSet);
  check("'once' does not cache", !onceSet.has("RW"));

  await store.close();
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(failures === 0 ? "\nALL PASSED" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
