/** Shortest secret value we will scrub. Below this, false positives dominate. */
const MIN_SCRUB_LEN = 4;

/** The placeholder substituted for each redacted secret occurrence. */
export const REDACTION = "***";

/**
 * Replace every literal occurrence of each secret value in `text` with `***`.
 *
 * This is keymaxxer's safety net: even though secrets are injected only as
 * environment variables, a command like `echo $TOKEN` would otherwise echo the
 * value straight back to the agent. Longer values are scrubbed first so that a
 * secret that is a substring of another does not leave a partial leak.
 */
export function scrub(
  text: string,
  values: string[],
): { text: string; redactions: number } {
  const unique = [...new Set(values.filter((v) => v.length >= MIN_SCRUB_LEN))].sort(
    (a, b) => b.length - a.length,
  );

  let out = text;
  let redactions = 0;
  for (const value of unique) {
    const parts = out.split(value);
    if (parts.length > 1) {
      redactions += parts.length - 1;
      out = parts.join(REDACTION);
    }
  }
  return { text: out, redactions };
}
