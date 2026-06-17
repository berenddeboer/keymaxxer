import { spawn } from "node:child_process";
import { scrub } from "./scrubber.js";
import type { RunResult } from "./types.js";

export interface RunnerOptions {
  command: string;
  /** Map of secret name -> value, injected into the child environment. */
  env: Record<string, string>;
  cwd?: string;
  timeoutMs?: number;
}

/**
 * Run `command` through the system shell with the given secrets present in the
 * child environment. The command references them as `$NAME`; the value never
 * appears in any argv that keymaxxer constructs. Captured stdout/stderr are scrubbed
 * of every secret value before returning.
 */
export function runWithSecrets(opts: RunnerOptions): Promise<RunResult> {
  const values = Object.values(opts.env);

  return new Promise((resolve) => {
    const child = spawn(opts.command, {
      shell: true,
      cwd: opts.cwd ?? process.cwd(),
      env: { ...process.env, ...opts.env },
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
        }, opts.timeoutMs)
      : null;

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    const finish = (exitCode: number | null, extraStderr = "") => {
      if (timer) clearTimeout(timer);
      const so = scrub(stdout, values);
      const se = scrub(stderr + extraStderr, values);
      resolve({
        stdout: so.text,
        stderr: se.text,
        exitCode,
        redactions: so.redactions + se.redactions,
      });
    };

    child.on("error", (err) => finish(null, `\n[keymaxxer] failed to spawn command: ${err.message}`));
    child.on("close", (code) =>
      finish(code, timedOut ? `\n[keymaxxer] command killed after ${opts.timeoutMs}ms timeout` : ""),
    );
  });
}
