import { connect } from "node:net";
import type { AuditEntry, RunRequest, RunResult, SecretFields, SecretMeta } from "keymaxxer-sdk";

/**
 * Newline-delimited JSON protocol spoken over the agent's unix socket. One
 * request and one response per connection. Secret values never appear in any
 * request or response — only names, scrubbed output, and metadata.
 */
export type Request =
  | { op: "status" }
  | { op: "lock" }
  | { op: "list" }
  | { op: "run"; req: RunRequest }
  | { op: "set"; name: string; value: string; fields: SecretFields }
  | { op: "remove"; name: string }
  | { op: "audit"; limit: number };

export type Response =
  | { ok: true; result: unknown }
  | { ok: false; error: string };

export interface StatusResult {
  unlocked: true;
  vault: string;
  idleSeconds: number;
  idleTimeoutSeconds: number;
  /** Sensitive secrets approved "for the session" (no re-prompt until lock). */
  sessionApproved: string[];
}

export type { SecretMeta, RunResult, AuditEntry };

/** Send a single request to the daemon socket and resolve its response. */
export function sendRequest(socket: string, req: Request, timeoutMs = 0): Promise<Response> {
  return new Promise((resolve, reject) => {
    const conn = connect(socket);
    let data = "";
    if (timeoutMs > 0) conn.setTimeout(timeoutMs, () => conn.destroy(new Error("request timed out")));
    conn.on("connect", () => conn.write(JSON.stringify(req) + "\n"));
    conn.on("data", (chunk) => {
      data += chunk.toString();
      const nl = data.indexOf("\n");
      if (nl >= 0) {
        conn.end();
        try {
          resolve(JSON.parse(data.slice(0, nl)) as Response);
        } catch (err) {
          reject(new Error("malformed response from agent"));
        }
      }
    });
    conn.on("error", reject);
  });
}
