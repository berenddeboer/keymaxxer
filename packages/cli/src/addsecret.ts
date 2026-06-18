import { spawn } from "node:child_process";
import type { SecretFields } from "keymaxxer-sdk";

/** Attributes an agent suggests for a new secret; the human reviews/edits them. */
export interface AddSuggestion {
  name: string;
  provider?: string;
  account?: string;
  environment?: string;
  access?: string;
  tags?: string;
  description?: string;
}

export interface AddResult {
  name: string;
  value: string;
  fields: SecretFields;
}

function asAppleScript(s: string): string {
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ") + '"';
}

/**
 * Show a native dialog with one (visible) editable text field. Resolves the
 * entered text, or null if cancelled / dismissed / not on macOS.
 */
function dialog(message: string, prefill: string, saveLabel: string): Promise<string | null> {
  if (process.platform !== "darwin") return Promise.resolve(null);
  return new Promise((resolve) => {
    const script =
      `display dialog ${asAppleScript(message)} default answer ${asAppleScript(prefill)} ` +
      `with title "keymaxxer — add secret" with icon note ` +
      `buttons {"Cancel", ${asAppleScript(saveLabel)}} default button ${asAppleScript(saveLabel)} ` +
      `cancel button "Cancel" giving up after 180`;
    const proc = spawn("osascript", ["-e", script]);
    let out = "";
    proc.stdout.on("data", (c) => (out += c.toString()));
    proc.on("error", () => resolve(null));
    proc.on("close", (code) => {
      if (code !== 0) return resolve(null); // Cancel / Esc
      if (/gave up:true/.test(out)) return resolve(null);
      const m = out.match(/text returned:([\s\S]*?)(?:, gave up:[^,]*)?$/);
      resolve(m ? m[1].replace(/\n$/, "") : "");
    });
  });
}

/**
 * Show a message-only dialog (no input field) so a long value wraps and is fully
 * readable. Resolves "save", "edit", or null (dismissed / timed out / not macOS).
 */
function confirm(message: string): Promise<"save" | "edit" | null> {
  if (process.platform !== "darwin") return Promise.resolve(null);
  return new Promise((resolve) => {
    const lines = message.split("\n");
    const heading = asAppleScript(lines[0] ?? "");
    const rest = lines.slice(1).map(asAppleScript).join(" & return & ") || '""';
    const script =
      `display alert ${heading} message (${rest}) as informational ` +
      `buttons {"Edit", "Save"} default button "Save" giving up after 180`;
    const proc = spawn("osascript", ["-e", script]);
    let out = "";
    proc.stdout.on("data", (c) => (out += c.toString()));
    proc.on("error", () => resolve(null));
    proc.on("close", (code) => {
      if (code !== 0) return resolve(null);
      if (/gave up:true/.test(out)) return resolve(null);
      if (/button returned:Save/.test(out)) return resolve("save");
      if (/button returned:Edit/.test(out)) return resolve("edit");
      return resolve(null);
    });
  });
}

/** Split a string into tokens, honouring double quotes (and empty "" tokens). */
function tokenize(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  let started = false;
  for (const ch of s) {
    if (ch === '"') {
      inQuote = !inQuote;
      started = true;
    } else if (ch === " " && !inQuote) {
      if (started || cur) out.push(cur);
      cur = "";
      started = false;
    } else {
      cur += ch;
      started = true;
    }
  }
  if (started || cur) out.push(cur);
  return out;
}

/** Parse `--flag value` tokens into structured secret attributes. */
function tokensToFields(tokens: string[]): SecretFields {
  const flags: Record<string, string> = {};
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (!t.startsWith("--")) continue;
    const key = t.slice(2);
    const next = tokens[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = "";
    }
  }
  const fields: SecretFields = {};
  const pick = (...keys: string[]) => keys.map((k) => flags[k]).find((v) => v);
  const tag = pick("tag", "tags");
  if (tag) fields.tags = tag.split(",");
  const provider = pick("provider");
  if (provider) fields.provider = provider;
  const account = pick("account");
  if (account) fields.account = account;
  const environment = pick("env", "environment");
  if (environment) fields.environment = environment;
  const access = pick("access");
  if (access) fields.access = access;
  const description = pick("description", "desc");
  if (description) fields.description = description;
  return fields;
}

/**
 * The editable attribute line shown in the first dialog. Only the flags the
 * agent actually suggested are pre-filled, so the line stays short and readable
 * (a long pre-filled line scrolls the field to its end and hides the name).
 */
export function suggestionLine(s: AddSuggestion): string {
  const q = (v: string) => `"${v.replace(/"/g, "'")}"`;
  const parts = [s.name];
  if (s.provider) parts.push(`--provider ${q(s.provider)}`);
  if (s.account) parts.push(`--account ${q(s.account)}`);
  if (s.environment) parts.push(`--env ${q(s.environment)}`);
  if (s.access) parts.push(`--access ${q(s.access)}`);
  if (s.tags) parts.push(`--tag ${q(s.tags)}`);
  if (s.description) parts.push(`--description ${q(s.description)}`);
  return parts.join(" ");
}

/** Parse an edited attribute line back into a name + fields. */
export function parseSuggestionLine(line: string): { name: string; fields: SecretFields } {
  const tokens = tokenize(line.trim());
  const name = tokens[0];
  if (!name || name.startsWith("--")) throw new Error("a secret name is required.");
  return { name, fields: tokensToFields(tokens.slice(1)) };
}

/**
 * Prompt the human to add a secret via two visible dialogs: (1) the name +
 * attributes (pre-filled, editable), then (2) the value. The value is visible —
 * it goes straight to the vault, never to the agent. Returns null if cancelled.
 */
export async function promptAddSecret(s: AddSuggestion): Promise<AddResult | null> {
  const edited = await dialog(
    "Edit the new secret's name and attributes. Available flags: --provider --account --env --access --tag --description",
    suggestionLine(s),
    "Next",
  );
  if (edited === null) return null;
  const { name, fields } = parseSuggestionLine(edited);

  // Enter the value, then confirm it on a wrapped, fully-readable screen (the
  // single-line input field hides long tokens behind their tail). "Edit" loops
  // back with the entered value pre-filled so it can be corrected.
  let value = "";
  for (;;) {
    const entered = await dialog(
      `Value for ${name} — saved to the vault, never shared with the agent:`,
      value,
      "Review",
    );
    if (entered === null) return null;
    if (!entered) throw new Error("no value provided.");
    value = entered;

    const choice = await confirm(`Save this value for ${name}?\n\n${value}`);
    if (choice === "save") break;
    if (choice === null) return null;
    // "edit" → loop, re-showing the value for correction
  }
  return { name, value, fields };
}
