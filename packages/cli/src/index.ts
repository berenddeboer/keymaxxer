#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import {
  DEFAULT_CIPHER,
  SecretStore,
  WrongKeyError,
  deriveKey,
  generateSalt,
  loadMeta,
  newExternalKeyMeta,
  newPassphraseMeta,
  saveMeta,
  type SecretFields,
} from "keymaxxer-sdk";
import { runAgent } from "./agent.js";
import {
  agentStatus,
  getClient,
  isAgentAlive,
  lockAgent,
  spawnAgent,
} from "./client.js";
import { manualSnippet, wireMcpJson } from "./init.js";
import { serve } from "./mcp.js";
import { vaultPath } from "./paths.js";
import { readHiddenLine, readNewPassphrase, readPassphrase } from "./prompt.js";

const HELP = `keymaxxer — a secret manager for coding agents

Setup:
  keymaxxer init                 Create the encrypted vault (prompts for a passphrase)
  keymaxxer unlock [--timeout m]  Unlock the vault into the background agent (default 15m idle)
  keymaxxer lock                 Lock the vault and stop the agent
  keymaxxer status               Show whether the vault is unlocked

Secrets (require an unlocked vault, or KEYMAXXER_MASTER_KEY):
  keymaxxer set <NAME> [attrs]   Store a secret; prompts to paste the value (hidden),
                             or pipe it in. attrs: --provider --account --env --access --tag --description
  keymaxxer import <file>        Import KEY=VALUE lines from a .env-style file
  keymaxxer list                 List secret names + metadata (never values)
  keymaxxer rm <NAME>            Delete a secret
  keymaxxer run --secrets a,b -- <cmd>   Run a command with secrets injected as env vars
  keymaxxer audit [--limit N]    Show recent secret-access log

Agent integration:
  keymaxxer serve                Start the MCP server on stdio (proxies to the agent)

The encryption key is derived from your passphrase and never stored at rest.
For CI, set KEYMAXXER_MASTER_KEY (64-hex) and skip unlock entirely.`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

function parseArgs(argv: string[]) {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const rest: string[] = [];
  let afterDashDash = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (afterDashDash) rest.push(a);
    else if (a === "--") afterDashDash = true;
    else if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else flags[key] = true;
    } else positionals.push(a);
  }
  return { positionals, flags, rest };
}

function die(msg: string): never {
  console.error(`keymaxxer: ${msg}`);
  process.exit(1);
}

/** Build the structured secret attributes from CLI flags. */
function fieldsFromFlags(flags: Record<string, string | boolean>): SecretFields {
  const str = (...keys: string[]): string | undefined => {
    for (const k of keys) if (typeof flags[k] === "string") return flags[k] as string;
    return undefined;
  };
  const fields: SecretFields = {};
  const tag = str("tag", "tags");
  if (tag) fields.tags = tag.split(",");
  const provider = str("provider");
  if (provider) fields.provider = provider;
  const account = str("account");
  if (account) fields.account = account;
  const environment = str("env", "environment");
  if (environment) fields.environment = environment;
  const access = str("access");
  if (access) fields.access = access;
  const description = str("description", "desc");
  if (description) fields.description = description;
  return fields;
}

async function main() {
  const [cmd, ...argv] = process.argv.slice(2);
  const { positionals, flags, rest } = parseArgs(argv);

  switch (cmd) {
    case undefined:
    case "help":
    case "-h":
    case "--help":
      console.log(HELP);
      return;

    case "__agent": // internal: the daemon entry point
      await runAgent();
      return;

    case "init": {
      if (loadMeta(vaultPath()) && existsSync(vaultPath())) {
        die("a vault already exists at " + vaultPath());
      }
      const envKey = process.env.KEYMAXXER_MASTER_KEY;
      if (envKey) {
        await SecretStore.open({ path: vaultPath(), hexkey: envKey.toLowerCase() });
        saveMeta(vaultPath(), newExternalKeyMeta(DEFAULT_CIPHER));
        console.log(`✓ Vault created at ${vaultPath()} using KEYMAXXER_MASTER_KEY (AES-256-GCM).`);
      } else {
        const passphrase = await readNewPassphrase();
        const salt = generateSalt();
        const hexkey = deriveKey(passphrase, salt);
        const store = await SecretStore.open({ path: vaultPath(), hexkey });
        await store.close();
        saveMeta(vaultPath(), newPassphraseMeta(DEFAULT_CIPHER, salt));
        console.log(`✓ Vault created at ${vaultPath()} (key derived from your passphrase, AES-256-GCM).`);
        await spawnAgent(hexkey);
        console.log("✓ Vault unlocked into the background agent.");
      }
      console.log(wireMcpJson(process.cwd()));
      console.log("\nFor editors not auto-configured, add this MCP server:");
      console.log(manualSnippet());
      return;
    }

    case "unlock": {
      const meta = loadMeta(vaultPath());
      if (!meta || !existsSync(vaultPath())) die("no vault found. Run `keymaxxer init` first.");
      if (meta.kdf === "none") {
        die("this vault uses an external key — set KEYMAXXER_MASTER_KEY; no unlock needed.");
      }
      if (await isAgentAlive()) {
        console.log("Vault is already unlocked.");
        return;
      }
      const passphrase = await readPassphrase("Vault passphrase: ");
      const hexkey = deriveKey(passphrase, meta.salt!, meta.scrypt);
      // Verify before spawning so a wrong passphrase gives a clear error.
      try {
        const probe = await SecretStore.open({ path: vaultPath(), hexkey });
        await probe.close();
      } catch (err) {
        if (err instanceof WrongKeyError) die("wrong passphrase.");
        throw err;
      }
      const timeout = typeof flags.timeout === "string" ? Number(flags.timeout) : undefined;
      await spawnAgent(hexkey, timeout);
      const st = await agentStatus();
      console.log(`✓ Vault unlocked (auto-locks after ${st ? st.idleTimeoutSeconds / 60 : 15}m idle).`);
      return;
    }

    case "lock": {
      const stopped = await lockAgent();
      console.log(stopped ? "✓ Vault locked." : "Vault was not unlocked.");
      return;
    }

    case "status": {
      const st = await agentStatus();
      if (!st) {
        console.log(process.env.KEYMAXXER_MASTER_KEY ? "Unlocked via KEYMAXXER_MASTER_KEY." : "Locked.");
        return;
      }
      console.log(`Unlocked — vault ${st.vault}, idle ${st.idleSeconds}s / ${st.idleTimeoutSeconds}s timeout.`);
      return;
    }

    case "set": {
      const name =
        positionals[0] ??
        die("usage: keymaxxer set <NAME> [--provider p] [--account a] [--env e] [--access a] [--tag t] [--description d]");
      // Interactive: prompt and let the user paste (hidden, never echoed, never
      // in shell history). Piped: read the value from stdin for scripting.
      const value = process.stdin.isTTY
        ? await readHiddenLine(`Value for ${name} (paste — input is hidden): `)
        : await readStdin();
      if (!value) die("no value provided.");
      const client = await getClient();
      await client.set(name, value, fieldsFromFlags(flags));
      await client.close();
      console.log(`✓ Stored '${name}'.`);
      return;
    }

    case "import": {
      const file = positionals[0] ?? die("usage: keymaxxer import <file>");
      if (!existsSync(file)) die(`file not found: ${file}`);
      const text = readFileSync(file, "utf8");
      const client = await getClient();
      let count = 0;
      for (const raw of text.split("\n")) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq < 1) continue;
        const key = line.slice(0, eq).trim().replace(/^export\s+/, "");
        let val = line.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        await client.set(key, val, {});
        count++;
      }
      await client.close();
      console.log(`✓ Imported ${count} secret(s) from ${file}.`);
      return;
    }

    case "list": {
      const client = await getClient();
      const metas = await client.list();
      await client.close();
      if (metas.length === 0) {
        console.log("No secrets yet. Add one: printf %s 'value' | keymaxxer set NAME");
        return;
      }
      for (const m of metas) {
        const used = m.lastUsedAt ? `last used ${m.lastUsedAt}` : "never used";
        const tags = m.tags.length ? ` [${m.tags.join(", ")}]` : "";
        const attrs = [m.provider, m.account, m.environment, m.access].filter(Boolean).join(" · ");
        const head = `${m.name}${tags}`;
        console.log(attrs ? `${head}  (${attrs})  —  ${used}` : `${head}  —  ${used}`);
        if (m.description) console.log(`    ${m.description}`);
      }
      return;
    }

    case "rm": {
      const name = positionals[0] ?? die("usage: keymaxxer rm <NAME>");
      const client = await getClient();
      const removed = await client.remove(name);
      await client.close();
      console.log(removed ? `✓ Removed '${name}'.` : `'${name}' not found.`);
      return;
    }

    case "run": {
      const command = rest.join(" ");
      if (!command) die("usage: keymaxxer run --secrets a,b -- <command...>");
      const secrets =
        typeof flags.secrets === "string" && flags.secrets.length ? flags.secrets.split(",") : [];
      const timeoutMs = typeof flags.timeout === "string" ? Number(flags.timeout) : undefined;
      const client = await getClient();
      const res = await client.run({ command, secrets, timeoutMs });
      await client.close();
      if (res.stdout) process.stdout.write(res.stdout.endsWith("\n") ? res.stdout : res.stdout + "\n");
      if (res.stderr) process.stderr.write(res.stderr.endsWith("\n") ? res.stderr : res.stderr + "\n");
      if (res.redactions > 0) console.error(`[keymaxxer] redacted ${res.redactions} secret occurrence(s)`);
      process.exit(res.exitCode ?? 1);
    }

    case "audit": {
      const limit = typeof flags.limit === "string" ? Number(flags.limit) : 20;
      const client = await getClient();
      const entries = await client.audit(limit);
      await client.close();
      if (entries.length === 0) {
        console.log("No audit entries yet.");
        return;
      }
      for (const e of entries) {
        const status = e.outcome === "denied" ? "DENIED" : `exit=${e.exitCode}`;
        console.log(`${e.ts}  ${status}  [${e.secrets.join(", ")}]  ${e.command}`);
      }
      return;
    }

    case "serve":
    case "mcp":
      await serve();
      return;

    default:
      die(`unknown command '${cmd}'. Run \`keymaxxer help\`.`);
  }
}

main().catch((err) => die(err instanceof Error ? err.message : String(err)));
