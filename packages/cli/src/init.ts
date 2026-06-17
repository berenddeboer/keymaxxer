import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The MCP server entry keymaxxer installs into editor configs.
 *
 * When keymaxxer is run from a source checkout (a `.ts` entry point), we wire the
 * absolute path so `bun <path> serve` works without publishing. Once installed
 * from npm, we use `npx keymaxxer serve`.
 */
function keymaxxerServerEntry() {
  const entry = process.argv[1] ?? "";
  if (entry.endsWith(".ts")) {
    return { command: "bun", args: [entry, "serve"] };
  }
  return { command: "npx", args: ["keymaxxer", "serve"] };
}

/**
 * Merge a `keymaxxer` server entry into a Claude Code / Cursor style `.mcp.json`
 * in the given directory. Creates the file if absent; leaves other servers
 * untouched. Returns a human-readable description of what happened.
 */
export function wireMcpJson(dir: string): string {
  const file = join(dir, ".mcp.json");
  let config: { mcpServers?: Record<string, unknown> } = {};

  if (existsSync(file)) {
    try {
      config = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return `Skipped ${file}: existing file is not valid JSON. Add the keymaxxer server manually.`;
    }
  }

  config.mcpServers ??= {};
  const existed = "keymaxxer" in config.mcpServers;
  config.mcpServers.keymaxxer = keymaxxerServerEntry();
  writeFileSync(file, JSON.stringify(config, null, 2) + "\n");
  return `${existed ? "Updated" : "Added"} 'keymaxxer' server in ${file}`;
}

/** The snippet to paste for editors we do not auto-configure. */
export function manualSnippet(): string {
  return JSON.stringify({ mcpServers: { keymaxxer: keymaxxerServerEntry() } }, null, 2);
}
