/**
 * Build the command needed to re-invoke this same CLI with extra arguments,
 * whether we are running from a `.ts` source entry under bun or as a compiled
 * standalone binary. Used to spawn the agent daemon as a child process.
 */
export function selfCommand(extraArgs: string[]): { cmd: string; args: string[] } {
  const entry = process.argv[1] ?? "";
  // Running as a script under a runtime (bun src/index.ts, node dist/cli.mjs):
  // re-invoke that same runtime with the script path.
  if (/\.(ts|js|mjs|cjs)$/.test(entry)) {
    return { cmd: process.execPath, args: [entry, ...extraArgs] };
  }
  // Compiled standalone binary: process.execPath is the keymaxxer binary itself.
  return { cmd: process.execPath, args: [...extraArgs] };
}
