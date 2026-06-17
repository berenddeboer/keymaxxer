/**
 * Build the command needed to re-invoke this same CLI with extra arguments,
 * whether we are running from a `.ts` source entry under bun or as a compiled
 * standalone binary. Used to spawn the agent daemon as a child process.
 */
export function selfCommand(extraArgs: string[]): { cmd: string; args: string[] } {
  // keymaxxer always runs as a script under a runtime: `bun src/index.ts`,
  // `node dist/cli.mjs`, or a node-symlinked global/npx bin (which may have no
  // file extension at all). Re-invoke the same runtime with the same entry —
  // node follows the symlink, bun runs the .ts. Do NOT key off the extension.
  const entry = process.argv[1];
  if (entry) return { cmd: process.execPath, args: [entry, ...extraArgs] };
  return { cmd: process.execPath, args: [...extraArgs] };
}
