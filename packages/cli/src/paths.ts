import { homedir } from "node:os";
import { join } from "node:path";

/** Directory holding the vault, agent socket, and pidfile. */
export function keymaxxerDir(): string {
  return join(homedir(), ".keymaxxer");
}

export function vaultPath(): string {
  return join(keymaxxerDir(), "vault.db");
}

/** Unix socket the agent daemon listens on. */
export function socketPath(): string {
  return join(keymaxxerDir(), "agent.sock");
}

export function pidPath(): string {
  return join(keymaxxerDir(), "agent.pid");
}

export function agentLogPath(): string {
  return join(keymaxxerDir(), "agent.log");
}
