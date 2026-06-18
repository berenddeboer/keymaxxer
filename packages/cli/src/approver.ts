import { spawn } from "node:child_process";
import type { SecretMeta } from "keymaxxer-sdk";

/**
 * A secret is "sensitive" — and therefore requires interactive approval before
 * an agent may use it — when it is read-write/admin or targets production.
 * Read-only / non-prod (and unclassified) secrets are used without prompting.
 */
export function isSensitive(m: SecretMeta): boolean {
  const access = (m.access ?? "").toLowerCase();
  const env = (m.environment ?? "").toLowerCase();
  const writeish = access.includes("write") || access.includes("admin");
  const prod = env === "prod" || env === "production";
  return writeish || prod;
}

export interface ApprovalRequest {
  secrets: SecretMeta[];
  command: string;
  cwd: string;
}

/** Quote a string for safe interpolation into an AppleScript literal. */
function asQuote(s: string): string {
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ") + '"';
}

function describe(req: ApprovalRequest): string[] {
  const names = req.secrets
    .map((s) => `${s.name} (${[s.provider, s.environment, s.access].filter(Boolean).join(" / ")})`)
    .join(", ");
  const cmd = req.command.length > 200 ? req.command.slice(0, 197) + "..." : req.command;
  return [
    "An agent wants to USE a sensitive secret:",
    `Secret: ${names}`,
    `Command: ${cmd}`,
    `Dir: ${req.cwd}`,
    "Allow once = this command. Allow session = until the vault locks.",
  ];
}

/** A user's response to an approval prompt. */
export type ApprovalDecision = "deny" | "once" | "session";

/** Pop a native macOS dialog and resolve the user's choice. */
function approveViaOsascript(req: ApprovalRequest): Promise<ApprovalDecision> {
  return new Promise((resolve) => {
    const body = describe(req).map(asQuote).join(" & return & ");
    const script =
      `display dialog ${body} with title "keymaxxer — approve secret use" ` +
      `buttons {"Deny", "Allow once", "Allow session"} default button "Allow once" ` +
      `cancel button "Deny" giving up after 60`;
    const proc = spawn("osascript", ["-e", script]);
    let out = "";
    proc.stdout.on("data", (c) => (out += c.toString()));
    proc.on("error", () => resolve("deny")); // osascript missing → fail closed
    proc.on("close", (code) => {
      if (code !== 0) return resolve("deny"); // Deny / Esc
      if (/button returned:Allow session/.test(out)) return resolve("session");
      if (/button returned:Allow once/.test(out)) return resolve("once");
      return resolve("deny"); // timed out / unknown
    });
  });
}

/**
 * Ask the human to approve a sensitive secret use. Returns "deny", "once" (this
 * command only), or "session" (allow this secret until the vault locks). The
 * `KEYMAXXER_APPROVE` env forces a decision (deny | once | allow | session) for
 * headless/CI use and tests. Otherwise we prompt natively on macOS; with no
 * interactive channel we fail closed (deny).
 */
export async function requestApproval(req: ApprovalRequest): Promise<ApprovalDecision> {
  const override = (process.env.KEYMAXXER_APPROVE ?? "").toLowerCase();
  if (override === "deny") return "deny";
  if (override === "session") return "session";
  if (override === "allow" || override === "once") return "once";
  if (process.platform === "darwin") return approveViaOsascript(req);
  return "deny";
}
