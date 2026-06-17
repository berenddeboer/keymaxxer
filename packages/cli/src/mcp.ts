import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { getClient } from "./client.js";

/**
 * Start the keymaxxer MCP server on stdio. It holds no key: every call is resolved
 * through the agent daemon (or an env key in CI). The agent never receives a
 * raw secret value — keymaxxer_list returns names only, keymaxxer_run returns scrubbed
 * output.
 */
export async function serve(): Promise<void> {
  const server = new McpServer({ name: "keymaxxer", version: "0.1.0" });

  server.registerTool(
    "keymaxxer_list",
    {
      description:
        "List the secrets in the vault with their attributes — name, provider (e.g. github/orb/stripe), account, environment (prod/dev/staging), access level (read-only/read-write/admin), tags, and description. Returns NO secret values. Call this first to discover which secrets exist AND to choose the correct one: match the provider/account the task targets, prefer the right environment, and prefer the least-privileged credential that can do the job (e.g. a read-only key when you're only reading).",
      inputSchema: {},
    },
    async () => {
      try {
        const client = await getClient();
        const metas = await client.list();
        await client.close();
        return { content: [{ type: "text", text: JSON.stringify(metas, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text", text: errText(err) }], isError: true };
      }
    },
  );

  server.registerTool(
    "keymaxxer_run",
    {
      description:
        "Run a shell command with secrets injected as environment variables. Reference each secret as $NAME (e.g. \"gh api /user\" with GITHUB_TOKEN, or curl -H \"Authorization: Bearer $TOKEN\"). Secret values are injected into the child process only; they are scrubbed from the returned output and never exposed to you. Use keymaxxer_list to find available names. Note: read-write or production secrets are gated — the human is asked to approve the use, so the call may pause briefly and can be denied; if denied, pick a less-privileged secret or ask the user.",
      inputSchema: {
        command: z.string().describe("Shell command to run. Reference secrets as $NAME."),
        secrets: z.array(z.string()).describe("Names of secrets to inject as environment variables."),
        cwd: z.string().optional().describe("Working directory. Defaults to the agent's cwd."),
        timeoutMs: z.number().optional().describe("Kill the command after this many milliseconds."),
      },
    },
    async (args) => {
      try {
        const client = await getClient();
        const res = await client.run(args);
        await client.close();
        const lines = [
          `exit_code: ${res.exitCode}`,
          res.redactions > 0 ? `[keymaxxer] redacted ${res.redactions} secret occurrence(s)` : null,
          `--- stdout ---`,
          res.stdout,
          `--- stderr ---`,
          res.stderr,
        ].filter((l) => l !== null);
        return { content: [{ type: "text", text: lines.join("\n") }], isError: res.exitCode !== 0 };
      } catch (err) {
        return { content: [{ type: "text", text: errText(err) }], isError: true };
      }
    },
  );

  await server.connect(new StdioServerTransport());
}

function errText(err: unknown): string {
  return `error: ${err instanceof Error ? err.message : String(err)}`;
}
