import { homedir } from "node:os";
import { join } from "node:path";

/** Directory holding the vault and its metadata. */
export function keymaxxerDir(): string {
  return join(homedir(), ".keymaxxer");
}

export function vaultPath(): string {
  return join(keymaxxerDir(), "vault.db");
}
