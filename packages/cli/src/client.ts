import { spawn } from "node:child_process";
import { existsSync, unlinkSync } from "node:fs";
import {
  SecretStore,
  type AuditEntry,
  type RunRequest,
  type RunResult,
  type SecretFields,
  type SecretMeta,
} from "keymaxxer-sdk";
import { pidPath, socketPath, vaultPath } from "./paths.js";
import { sendRequest, type Request, type Response, type StatusResult } from "./protocol.js";
import { selfCommand } from "./self.js";

const HEX64 = /^[0-9a-fA-F]{64}$/;

/** Uniform vault interface, backed by either the agent daemon or a direct store. */
export interface VaultClient {
  list(): Promise<SecretMeta[]>;
  run(req: RunRequest): Promise<RunResult>;
  set(name: string, value: string, fields: SecretFields): Promise<void>;
  remove(name: string): Promise<boolean>;
  audit(limit: number): Promise<AuditEntry[]>;
  close(): Promise<void>;
}

function unwrap(res: Response): unknown {
  if (!res.ok) throw new Error(res.error);
  return res.result;
}

/** Talks to the running agent daemon over its unix socket. */
class DaemonClient implements VaultClient {
  private call(req: Request): Promise<unknown> {
    return sendRequest(socketPath(), req).then(unwrap);
  }
  list() {
    return this.call({ op: "list" }) as Promise<SecretMeta[]>;
  }
  run(req: RunRequest) {
    return this.call({ op: "run", req }) as Promise<RunResult>;
  }
  async set(name: string, value: string, fields: SecretFields) {
    await this.call({ op: "set", name, value, fields });
  }
  remove(name: string) {
    return this.call({ op: "remove", name }) as Promise<boolean>;
  }
  audit(limit: number) {
    return this.call({ op: "audit", limit }) as Promise<AuditEntry[]>;
  }
  async close() {
    /* connection-per-request; nothing to close */
  }
}

/** Opens the vault directly with an externally supplied key (CI / headless). */
class DirectStore implements VaultClient {
  private constructor(private store: SecretStore) {}
  static async open(hexkey: string): Promise<DirectStore> {
    return new DirectStore(await SecretStore.open({ path: vaultPath(), hexkey }));
  }
  list() {
    return this.store.list();
  }
  run(req: RunRequest) {
    return this.store.run(req);
  }
  set(name: string, value: string, fields: SecretFields) {
    return this.store.set(name, value, fields);
  }
  remove(name: string) {
    return this.store.remove(name);
  }
  audit(limit: number) {
    return this.store.recentAudit(limit);
  }
  close() {
    return this.store.close();
  }
}

/** True if a daemon is listening and responsive; cleans up stale socket/pid. */
export async function isAgentAlive(): Promise<boolean> {
  if (!existsSync(socketPath())) return false;
  try {
    const res = await sendRequest(socketPath(), { op: "status" }, 2000);
    return res.ok;
  } catch {
    // Stale socket left by a crashed daemon — remove it.
    for (const p of [socketPath(), pidPath()]) if (existsSync(p)) unlinkSync(p);
    return false;
  }
}

export async function agentStatus(): Promise<StatusResult | null> {
  if (!(await isAgentAlive())) return null;
  const res = await sendRequest(socketPath(), { op: "status" });
  return res.ok ? (res.result as StatusResult) : null;
}

/**
 * Resolve a vault client: the env key (CI) wins, otherwise the running daemon.
 * Throws a clear "locked" message when neither is available.
 */
export async function getClient(): Promise<VaultClient> {
  const envKey = process.env.KEYMAXXER_MASTER_KEY;
  if (envKey) {
    if (!HEX64.test(envKey)) throw new Error("KEYMAXXER_MASTER_KEY must be 64 hex characters.");
    return DirectStore.open(envKey.toLowerCase());
  }
  if (await isAgentAlive()) return new DaemonClient();
  throw new Error("vault is locked. Run `keymaxxer unlock` first (or set KEYMAXXER_MASTER_KEY).");
}

/** Tell the running daemon to lock and exit. Returns false if none was running. */
export async function lockAgent(): Promise<boolean> {
  if (!(await isAgentAlive())) return false;
  try {
    await sendRequest(socketPath(), { op: "lock" });
  } catch {
    /* the daemon exits as it replies; a dropped connection is expected */
  }
  return true;
}

/**
 * Spawn the agent daemon, hand it the key over stdin (never argv), and wait
 * until it is listening. The key is wiped from this process after handoff.
 */
export async function spawnAgent(hexkey: string, idleMinutes?: number): Promise<void> {
  if (await isAgentAlive()) throw new Error("vault is already unlocked.");

  const { cmd, args } = selfCommand(["__agent"]);
  const env = { ...process.env };
  delete env.KEYMAXXER_MASTER_KEY; // the daemon uses the passphrase-derived key
  if (idleMinutes) env.KEYMAXXER_IDLE_MINUTES = String(idleMinutes);

  const child = spawn(cmd, args, { detached: true, stdio: ["pipe", "ignore", "ignore"], env });
  child.stdin!.write(hexkey + "\n");
  child.stdin!.end();
  child.unref();

  // Wait for the daemon to come up (socket responds to status).
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    if (await isAgentAlive()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("agent did not start in time — check ~/.keymaxxer/agent.log");
}
