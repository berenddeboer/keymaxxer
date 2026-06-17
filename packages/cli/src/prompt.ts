// Non-TTY line reader, so a passphrase can be piped in (`printf pass | keymaxxer unlock`).
// Buffers stdin and hands out one line per request, supporting sequential reads.
let stdinAttached = false;
let buffer = "";
const queued: string[] = [];
const waiters: ((line: string) => void)[] = [];
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
}
function nextLine(): Promise<string> {
  attachStdinLines();
  const q = queued.shift();
  if (q !== undefined) return Promise.resolve(q);
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
          // Enter
          cleanup();
          process.stderr.write("\n");
          resolve(buf);
          return;
        } else if (code === 3) {
          // Ctrl-C
          cleanup();
          process.stderr.write("\n");
          process.exit(130);
        } else if (code === 127 || code === 8) {
          // Backspace / Delete
          buf = buf.slice(0, -1);
        } else if (code >= 32) {
          buf += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}

/**
 * Read a passphrase from the terminal without echoing it. In a non-interactive
 * context (no TTY), reads one line from stdin so it can be piped in.
 */
export function readPassphrase(promptText: string): Promise<string> {
  if (!process.stdin.isTTY) return nextLine();
  return readHiddenLine(promptText);
}

/** Prompt twice and confirm the two entries match. */
export async function readNewPassphrase(): Promise<string> {
  const a = await readPassphrase("Create a vault passphrase: ");
  if (a.length < 8) throw new Error("passphrase must be at least 8 characters.");
  const b = await readPassphrase("Confirm passphrase: ");
  if (a !== b) throw new Error("passphrases did not match.");
  return a;
}
