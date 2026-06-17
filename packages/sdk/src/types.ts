/**
 * Public metadata for a secret. Never includes the value. These attributes let
 * an agent pick the *right* credential — correct provider/account, correct
 * environment, least privilege — rather than guessing from the name alone.
 */
export interface SecretMeta {
  name: string;
  tags: string[];
  /** The system the credential is for, e.g. "orb", "github", "stripe". */
  provider: string | null;
  /** Which account/org the credential belongs to, e.g. "turso". */
  account: string | null;
  /** Deployment environment, e.g. "prod", "dev", "staging", "test". */
  environment: string | null;
  /** Privilege level, e.g. "read-only", "read-write", "admin". */
  access: string | null;
  /** Free-form human note. */
  description: string | null;
  createdAt: string;
  lastUsedAt: string | null;
}

/** Structured attributes accepted when storing a secret. All optional. */
export interface SecretFields {
  tags?: string[];
  provider?: string;
  account?: string;
  environment?: string;
  access?: string;
  description?: string;
}

/** A request to run a command with secrets injected as environment variables. */
export interface RunRequest {
  /** Shell command. Reference injected secrets as `$NAME`. */
  command: string;
  /** Names of secrets to inject into the child process environment. */
  secrets: string[];
  /** Working directory for the child process. Defaults to process.cwd(). */
  cwd?: string;
  /** Hard timeout in milliseconds. The child is SIGKILLed when exceeded. */
  timeoutMs?: number;
}

/** Result of a run. stdout/stderr have every literal secret value scrubbed. */
export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** Number of secret occurrences redacted from the captured output. */
  redactions: number;
}

/** A single audit-log record. */
export interface AuditEntry {
  ts: string;
  secrets: string[];
  command: string;
  cwd: string;
  exitCode: number | null;
  /** "ran" if the command executed; "denied" if approval was refused. */
  outcome: "ran" | "denied";
}
