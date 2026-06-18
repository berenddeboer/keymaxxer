import { spawn } from "node:child_process";

// Non-TTY line reader, so a passphrase can be piped in (`printf pass | keymaxxer unlock`).
// Buffers stdin and hands out one line per request; resolves null once stdin ends with
// nothing left (e.g. Claude Code's `!` runs commands with no usable stdin).
let stdinAttached = false;
let buffer = "";
let ended = false;
const queued: string[] = [];
const waiters: ((line: string | null) => void)[] = [];
function attachStdinLines(): void {
  if (stdinAttached) return;
  stdinAttached = true;
  process.stdin.on("data", (d: Buffer) => {
    buffer += d.toString();
    let nl: number;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).replace(/\r$/, "");
      buffer = buffer.slice(nl + 1);
      const w = waiters.shift();
      if (w) w(line);
      else queued.push(line);
    }
  });
  process.stdin.on("end", () => {
    ended = true;
    if (buffer.length) {
      queued.push(buffer); // trailing line with no newline (e.g. `printf %s pass`)
      buffer = "";
    }
    while (waiters.length) waiters.shift()!(queued.shift() ?? null);
  });
  process.stdin.resume();
}
function nextLine(): Promise<string | null> {
  attachStdinLines();
  const q = queued.shift();
  if (q !== undefined) return Promise.resolve(q);
  if (ended) return Promise.resolve(null);
  return new Promise((res) => waiters.push(res));
}

/**
 * Read a single line from the terminal without echoing it (so a pasted secret
 * or passphrase never shows on screen and never reaches shell history). Assumes
 * an interactive TTY — callers should check `process.stdin.isTTY` first.
 */
export function readHiddenLine(promptText: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stderr.write(promptText);
    stdin.setRawMode(true);
    stdin.resume();

    let buf = "";
    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off("data", onData);
    };
    const onData = (d: Buffer) => {
      for (const ch of d.toString("utf8")) {
        const code = ch.charCodeAt(0);
        if (code === 13 || code === 10) {
          cleanup();
          process.stderr.write("\n");
          resolve(buf);
          return;
        } else if (code === 3) {
          cleanup();
          process.stderr.write("\n");
          process.exit(130);
        } else if (code === 127 || code === 8) {
          buf = buf.slice(0, -1);
        } else if (code >= 32) {
          buf += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}

function asAppleScript(s: string): string {
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ") + '"';
}

/**
 * Pop a native macOS dialog with a hidden text field and resolve the entered
 * passphrase — or null if cancelled, dismissed, or not on macOS. This is how
 * unlocking works from a context with no stdin (Claude Code's `!`, or an agent
 * tool call that hits a locked vault).
 */
export function promptPassphraseGui(message: string): Promise<string | null> {
  if (process.platform !== "darwin") return Promise.resolve(null);
  return new Promise((resolve) => {
    const script =
      `display dialog ${asAppleScript(message)} default answer "" with hidden answer ` +
      `with icon note with title "keymaxxer — unlock vault" ` +
      `buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel" ` +
      `giving up after 120`;
    const proc = spawn("osascript", ["-e", script]);
    let out = "";
    proc.stdout.on("data", (c) => (out += c.toString()));
    proc.on("error", () => resolve(null)); // osascript missing
    proc.on("close", (code) => {
      if (code !== 0) return resolve(null); // Cancel / Esc
      if (/gave up:true/.test(out)) return resolve(null); // timed out, no input
      const m = out.match(/text returned:([\s\S]*?)(?:, gave up:[^,]*)?$/);
      resolve(m ? m[1].replace(/\n$/, "") : "");
    });
  });
}

/**
 * Acquire a passphrase, trying every channel in order so it works everywhere:
 * the KEYMAXXER_PASSPHRASE env (headless/automation), an interactive TTY
 * (hidden), piped stdin (scripts), then a native GUI dialog (macOS).
 */
export async function readPassphrase(promptText: string): Promise<string> {
  const env = process.env.KEYMAXXER_PASSPHRASE;
  if (env) return env;
  if (process.stdin.isTTY) return readHiddenLine(promptText);
  const piped = await nextLine();
  if (piped) return piped;
  const gui = await promptPassphraseGui(promptText.replace(/:\s*$/, ""));
  if (gui) return gui;
  throw new Error("no passphrase provided (no TTY, no piped input, no GUI available).");
}

/** Prompt twice and confirm the two entries match. */
export async function readNewPassphrase(): Promise<string> {
  const a = await readPassphrase("Create a vault passphrase: ");
  if (a.length < 8) throw new Error("passphrase must be at least 8 characters.");
  const b = await readPassphrase("Confirm passphrase: ");
  if (a !== b) throw new Error("passphrases did not match.");
  return a;
}
