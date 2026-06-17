import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { DEFAULT_SCRYPT, type ScryptParams } from "./kdf.js";

/**
 * Non-secret metadata stored beside the vault. Records the cipher and how the
 * encryption key is produced, so a process can derive the same key from a
 * passphrase. Contains no key material — only a salt and KDF parameters.
 */
export interface VaultMeta {
  version: 1;
  cipher: string;
  /** "scrypt" = passphrase-derived; "none" = key supplied externally (env). */
  kdf: "scrypt" | "none";
  salt?: string;
  scrypt?: ScryptParams;
}

export function metaPath(vaultPath: string): string {
  return join(dirname(vaultPath), "vault.meta.json");
}

export function loadMeta(vaultPath: string): VaultMeta | null {
  const p = metaPath(vaultPath);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf8")) as VaultMeta;
}

export function saveMeta(vaultPath: string, meta: VaultMeta): void {
  mkdirSync(dirname(vaultPath), { recursive: true });
  writeFileSync(metaPath(vaultPath), JSON.stringify(meta, null, 2) + "\n");
}

/** Metadata for a new passphrase-protected vault. */
export function newPassphraseMeta(cipher: string, salt: string): VaultMeta {
  return { version: 1, cipher, kdf: "scrypt", salt, scrypt: DEFAULT_SCRYPT };
}

/** Metadata for a vault whose key is supplied externally (e.g. KEYMAXXER_MASTER_KEY). */
export function newExternalKeyMeta(cipher: string): VaultMeta {
  return { version: 1, cipher, kdf: "none" };
}
