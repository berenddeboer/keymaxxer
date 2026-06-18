import { existsSync } from "node:fs";
import {
  SecretStore,
  WrongKeyError,
  deriveKey,
  loadMeta,
  type RunRequest,
  type RunResult,
  type SecretMeta,
} from "keymaxxer-sdk";
import { isSensitive, requestApproval } from "./approver.js";
import { vaultPath } from "./paths.js";
import { promptPassphraseGui, readPassphrase } from "./prompt.js";

const HEX64 = /^[0-9a-fA-F]{64}$/;

/**
 * Open the encrypted vault. The key comes from KEYMAXXER_MASTER_KEY (CI), or is
 * derived from a passphrase obtained via `getPassphrase`. There is no daemon:
 * the caller holds the returned store (and thus the key) for as long as it lives
 * — an MCP server for the session, a CLI command for one invocation.
 */
async function openVault(getPassphrase: () => Promise<string | null>): Promise<SecretStore> {
  const envKey = process.env.KEYMAXXER_MASTER_KEY;
  if (envKey) {
    if (!HEX64.test(envKey)) throw new Error("KEYMAXXER_MASTER_KEY must be 64 hex characters.");
    return SecretStore.open({ path: vaultPath(), hexkey: envKey.toLowerCase() });
  }

  const meta = loadMeta(vaultPath());
  if (!meta || !existsSync(vaultPath())) throw new Error("no vault found. Run `keymaxxer init` first.");
  if (meta.kdf !== "scrypt" || !meta.salt) {
    throw new Error("this vault uses an external key — set KEYMAXXER_MASTER_KEY.");
  }

  const passphrase = await getPassphrase();
  if (!passphrase) throw new Error("no passphrase provided — vault stays locked.");

  const hexkey = deriveKey(passphrase, meta.salt, meta.scrypt);
  try {
    return await SecretStore.open({ path: vaultPath(), hexkey });
  } catch (err) {
    if (err instanceof WrongKeyError) throw new Error("wrong passphrase.");
    throw err;
  }
}

/** Open the vault from a CLI command (env key, or a passphrase from the terminal). */
export function openVaultCli(): Promise<SecretStore> {
  return openVault(() => readPassphrase("Vault passphrase: "));
}

/**
 * Open the vault from the MCP server, which has no usable stdin (that's the
 * protocol channel): the passphrase comes from KEYMAXXER_PASSPHRASE or a native
 * GUI dialog.
 */
export function openVaultServe(message: string): Promise<SecretStore> {
  return openVault(() =>
    process.env.KEYMAXXER_PASSPHRASE
      ? Promise.resolve(process.env.KEYMAXXER_PASSPHRASE)
      : promptPassphraseGui(message),
  );
}

/**
 * Run a command, gating sensitive (read-write / prod) secrets behind approval.
 * `approved` is the caller's set of already-approved secret names — for an MCP
 * server it lives for the whole session, so "Allow for the session" means until
 * the session ends. Throws on denial (and records it in the audit log).
 */
export async function runGated(
  store: SecretStore,
  req: RunRequest,
  approved: Set<string>,
): Promise<RunResult> {
  const metas = await store.list();
  const sensitive = req.secrets
    .map((n) => metas.find((m) => m.name === n))
    .filter((m): m is SecretMeta => !!m && isSensitive(m));
  const needPrompt = sensitive.filter((s) => !approved.has(s.name));

  if (needPrompt.length > 0) {
    const names = needPrompt.map((s) => s.name).join(", ");
    const decision = await requestApproval({
      secrets: needPrompt,
      command: req.command,
      cwd: req.cwd ?? process.cwd(),
    });
    if (decision === "deny") {
      await store.auditDenied(req.secrets, req.command, req.cwd ?? process.cwd());
      throw new Error(`Denied: use of ${names} was not approved by the user.`);
    }
    if (decision === "session") needPrompt.forEach((s) => approved.add(s.name));
  }
  return store.run(req);
}
