import { parseSuggestionLine, suggestionLine } from "./src/addsecret.js";

// The add-secret dialog itself needs a human, but the editable attribute line it
// shows is parsed back into name + fields — that round-trip is tested here.

let failures = 0;
function check(label: string, cond: boolean) {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) failures++;
}

// Round-trip a fully-specified suggestion.
const line = suggestionLine({
  name: "ORB_PROD",
  provider: "orb",
  account: "turso",
  environment: "prod",
  access: "read-write",
  description: "Orb prod token",
});
const a = parseSuggestionLine(line);
check("name round-trips", a.name === "ORB_PROD");
check("provider round-trips", a.fields.provider === "orb");
check("environment round-trips", a.fields.environment === "prod");
check("access round-trips", a.fields.access === "read-write");
check("quoted description with spaces", a.fields.description === "Orb prod token");

// A line the user edited: changed access, added tags, blanked account/description.
const edited =
  'GITHUB_TOKEN --provider "github" --account "" --env "dev" --access "read-only" --tag "ci,ro" --description ""';
const b = parseSuggestionLine(edited);
check("edited name", b.name === "GITHUB_TOKEN");
check("edited access", b.fields.access === "read-only");
check("edited tags split on comma", JSON.stringify(b.fields.tags) === JSON.stringify(["ci", "ro"]));
check("empty account is dropped", b.fields.account === undefined);
check("empty description is dropped", b.fields.description === undefined);

// A missing name is an error.
let threw = false;
try {
  parseSuggestionLine('--provider "x"');
} catch {
  threw = true;
}
check("a name is required", threw);

console.log(failures === 0 ? "\nALL PASSED" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
