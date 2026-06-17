import { appendFileSync, chmodSync, existsSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { SecretStore, type SecretMeta } from "keymaxxer-sdk";
import { isSensitive, requestApproval } from "./approver.js";
import { agentLogPath, pidPath, keymaxxerDir, socketPath, vaultPath } from "./paths.js";
import type { Request, Response, StatusResult } from "./protocol.js";

function log(msg: string): void {
  try {
    appendFileSync(agentLogPath(), `${new Date().toISOString()} ${msg}\n`);
  } catch {
    /* logging is best-effort */
  }
}

/** Read the hex key from the first line of stdin, then stop reading. */
function readKeyFromStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const onData = (chunk: Buffer) => {
      data += chunk.toString();
      const nl = data.indexOf("\n");
      if (nl >= 0) {
        process.stdin.off("data", onData);
        process.stdin.pause();
        resolve(data.slice(0, nl).trim());
      }
    };
    process.stdin.on("data", onData);
    process.stdin.on("end", () => reject(new Error("stdin closed before key was received")));
    process.stdin.on("error", reject);
  });
}

/**
 * The agent daemon. Holds the unlocked key + open vault in memory and serves
 * list/run/set/remove/audit over a unix socket until it is locked or idles out.
 * `run` executes here, so secret values never leave this process except into
 * the child it spawns.
 */
export async function runAgent(): Promise<void> {
  const sock = socketPath();
  const idleMs = Math.max(1, Number(process.env.KEYMAXXER_IDLE_MINUTES) || 15) * 60_000;

  const hexkey = await readKeyFromStdin();
  let store: SecretStore;
  try {
    store = await SecretStore.open({ path: vaultPath(), hexkey });
  } catch (err) {
    log(`failed to open vault: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }

  let lastActivity = Date.now();
  const unlockedAt = Date.now();

  const shutdown = (reason: string) => {
    log(`locking (${reason})`);
    if (existsSync(sock)) unlinkSync(sock);
    if (existsSync(pidPath())) unlinkSync(pidPath());
    process.exit(0);
  };

  const idleTimer = setInterval(() => {
    if (Date.now() - lastActivity > idleMs) shutdown("idle timeout");
  }, 5_000);
  idleTimer.unref();

  async function handle(req: Request): Promise<Response> {
    lastActivity = Date.now();
    try {
      switch (req.op) {
        case "status": {
          const result: StatusResult = {
            unlocked: true,
            vault: vaultPath(),
            idleSeconds: Math.floor((Date.now() - lastActivity) / 1000),
            idleTimeoutSeconds: Math.floor(idleMs / 1000),
          };
          return { ok: true, result };
        }
        case "list":
          return { ok: true, result: await store.list() };
        case "run": {
          // Sensitive secrets (read-write / prod) require interactive approval.
          const metas = await store.list();
          const sensitive = req.req.secrets
            .map((n) => metas.find((m) => m.name === n))
            .filter((m): m is SecretMeta => !!m && isSensitive(m));
          if (sensitive.length > 0) {
            const names = sensitive.map((s) => s.name).join(", ");
            const ok = await requestApproval({
              secrets: sensitive,
              command: req.req.command,
              cwd: req.req.cwd ?? process.cwd(),
            });
            if (!ok) {
              await store.auditDenied(req.req.secrets, req.req.command, req.req.cwd ?? process.cwd());
              log(`DENIED [${names}]: ${req.req.command}`);
              return { ok: false, error: `Denied: use of ${names} was not approved by the user.` };
            }
            log(`approved [${names}]`);
          }
          return { ok: true, result: await store.run(req.req) };
        }
        case "set":
          await store.set(req.name, req.value, req.fields);
          return { ok: true, result: null };
        case "remove":
          return { ok: true, result: await store.remove(req.name) };
        case "audit":
          return { ok: true, result: await store.recentAudit(req.limit) };
        case "lock":
          setTimeout(() => shutdown("explicit lock"), 10);
          return { ok: true, result: null };
        default:
          return { ok: false, error: `unknown op` };
      }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  const server = createServer((conn: Socket) => {
    let data = "";
    conn.on("data", async (chunk) => {
      data += chunk.toString();
      const nl = data.indexOf("\n");
      if (nl < 0) return;
      let req: Request;
      try {
        req = JSON.parse(data.slice(0, nl)) as Request;
      } catch {
        conn.end(JSON.stringify({ ok: false, error: "malformed request" }) + "\n");
        return;
      }
      const res = await handle(req);
      conn.end(JSON.stringify(res) + "\n");
    });
    conn.on("error", () => conn.destroy());
  });

  // Lock down the directory so no other user can reach the socket or files.
  mkdirSync(keymaxxerDir(), { recursive: true });
  try {
    chmodSync(keymaxxerDir(), 0o700);
  } catch {
    /* best-effort */
  }

  if (existsSync(sock)) unlinkSync(sock); // clear any stale socket
  server.listen(sock, () => {
    try {
      chmodSync(sock, 0o600); // only the owner may connect to the agent
    } catch {
      /* best-effort */
    }
    writeFileSync(pidPath(), String(process.pid));
    log(`unlocked, listening on ${sock} (idle ${idleMs / 60000}m)`);
  });
  server.on("error", (err) => {
    log(`server error: ${err.message}`);
    process.exit(1);
  });

  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.on(sig, () => shutdown(sig));
  }
  void unlockedAt;
}
