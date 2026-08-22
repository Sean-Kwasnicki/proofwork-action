import fs from "node:fs";
import path from "node:path";
const DEFAULT_GITIGNORE_SNIPPET = `
# Proofwork
.proofwork/proof-*.json
.proofwork/latest.json
.proofwork/latest.md
.proofwork/latest-brief.txt
.proofwork/latest-story.txt
.proofwork/ci-proof.json
.proofwork/ledger.json
.proofwork/deleted-fingerprints.json
.proofwork/ACCEPTANCE.json
`.trim();
const WORKFLOW = `name: Proofwork

on:
  pull_request:

jobs:
  gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      # Public compiled Action. Pin by commit SHA before enforcing.
      # gh api repos/Sean-Kwasnicki/proofwork-action/commits/v1 --jq .sha
      - uses: Sean-Kwasnicki/proofwork-action@v1
        with:
          fail-on: never
`;
const CONFIG = `{
  "failOnWarn": true,
  "strictAuth": false,
  "strictIntegrity": true,
  "maxIdenticalFailures": 2,
  "skipChecks": []
}
`;
const POLICY = `{
  "version": 1,
  "protected_paths": [
    ".github/workflows/",
    "proofwork.config.json",
    ".proofwork/config.json",
    ".proofwork/policy.json",
    ".cursor/hooks.json",
    ".cursor/hooks/proofwork-",
    ".cursor/rules/proofwork.mdc",
    ".cursor/mcp.json",
    "AGENTS.md"
  ]
}
`;
const HOOKS_JSON = `{
  "version": 1,
  "hooks": {
    "sessionStart": [{ "command": "node .cursor/hooks/proofwork-session.mjs" }],
    "afterShellExecution": [{ "command": "node .cursor/hooks/proofwork-after-shell.mjs" }],
    "stop": [{ "command": "node .cursor/hooks/proofwork-stop.mjs" }]
  }
}
`;
const MCP_JSON = `{
  "mcpServers": {
    "proofwork": {
      "command": "node",
      "args": [".cursor/run-proofwork-mcp.mjs"],
      "env": {
        "PROOFWORK_FAST": "1",
        "PROOFWORK_COMPACT": "1"
      }
    }
  }
}
`;
/** Consumer MCP launcher — resolves via PROOFWORK_HOME or .proofwork/install.json. */
const MCP_LAUNCHER = `#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readInstallHome() {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(projectRoot, ".proofwork", "install.json"), "utf8"));
    return j.proofwork_home ? String(j.proofwork_home) : "";
  } catch {
    return "";
  }
}

function resolveMcpJs() {
  for (const home of [process.env.PROOFWORK_HOME, readInstallHome()].filter(Boolean)) {
    const p = path.join(home, "dist", "mcp.js");
    if (fs.existsSync(p)) return p;
  }
  return "";
}

const mcpJs = resolveMcpJs();
if (!mcpJs) {
  process.stderr.write(
    "Proofwork MCP: set PROOFWORK_HOME to your built proofwork clone (dist/mcp.js), or re-run install-into.\\n",
  );
  process.exit(1);
}
process.chdir(path.dirname(path.dirname(mcpJs)));
process.env.PROOFWORK_FAST = process.env.PROOFWORK_FAST || "1";
process.env.PROOFWORK_COMPACT = process.env.PROOFWORK_COMPACT || "1";
await import(pathToFileURL(mcpJs).href);
`;
function resolveCliSnippet() {
    return `import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function installHome() {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(projectRoot, ".proofwork", "install.json"), "utf8"));
    return j.proofwork_home ? String(j.proofwork_home) : "";
  } catch { return ""; }
}

function runProofwork(args) {
  const home = process.env.PROOFWORK_HOME || installHome();
  if (home) {
    const cli = path.join(home, "dist", "cli.js");
    if (fs.existsSync(cli)) {
      return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", cwd: projectRoot });
    }
  }
  const bin = process.env.PROOFWORK_CLI || "proofwork";
  return spawnSync(bin, args, { encoding: "utf8", shell: true, cwd: projectRoot });
}
`;
}
function writeIfMissing(filePath, body, created, skipped, label) {
    if (fs.existsSync(filePath)) {
        skipped.push(label);
        return;
    }
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, body, "utf8");
    created.push(label);
}
export function initProofwork(root, opts = {}) {
    const created = [];
    const skipped = [];
    const dir = path.join(root, ".proofwork");
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        created.push(".proofwork/");
    }
    else {
        skipped.push(".proofwork/");
    }
    writeIfMissing(path.join(dir, ".gitkeep"), "", created, skipped, ".proofwork/.gitkeep");
    writeIfMissing(path.join(dir, "README.md"), `# Proofwork local state

- \`latest.json\` / \`latest-brief.txt\` / \`latest-story.txt\` — last Proof
- artefacts from \`proofwork report\` — not written into git

The Action on a pull request is the install. Cursor hooks and MCP are opt-in:
\`proofwork init --editor\`.
`, created, skipped, ".proofwork/README.md");
    const gi = path.join(root, ".gitignore");
    if (fs.existsSync(gi)) {
        const text = fs.readFileSync(gi, "utf8");
        if (!text.includes(".proofwork/latest.json")) {
            fs.appendFileSync(gi, `\n${DEFAULT_GITIGNORE_SNIPPET}\n`, "utf8");
            created.push(".gitignore (Proofwork snippet appended)");
        }
        else {
            skipped.push(".gitignore (already configured)");
        }
    }
    else {
        fs.writeFileSync(gi, `${DEFAULT_GITIGNORE_SNIPPET}\n`, "utf8");
        created.push(".gitignore");
    }
    writeIfMissing(path.join(root, ".github", "workflows", "proofwork.yml"), WORKFLOW, created, skipped, ".github/workflows/proofwork.yml");
    if (!opts.editor) {
        return { created, skipped };
    }
    const installPath = path.join(dir, "install.json");
    const installBody = {
        version: 1,
        mode: "editor-surface",
        installed_at: new Date().toISOString(),
        proofwork_home: opts.proofworkHome ? path.resolve(opts.proofworkHome) : process.env.PROOFWORK_HOME || null,
        bar: {
            strictIntegrity: true,
            failOnWarn: true,
            maxIdenticalFailures: 2,
        },
    };
    if (!fs.existsSync(installPath)) {
        fs.writeFileSync(installPath, `${JSON.stringify(installBody, null, 2)}\n`, "utf8");
        created.push(".proofwork/install.json");
    }
    else if (opts.proofworkHome) {
        try {
            const prev = JSON.parse(fs.readFileSync(installPath, "utf8"));
            prev.proofwork_home = path.resolve(opts.proofworkHome);
            prev.updated_at = new Date().toISOString();
            fs.writeFileSync(installPath, `${JSON.stringify(prev, null, 2)}\n`, "utf8");
            created.push(".proofwork/install.json (updated home)");
        }
        catch {
            fs.writeFileSync(installPath, `${JSON.stringify(installBody, null, 2)}\n`, "utf8");
            created.push(".proofwork/install.json (rewritten)");
        }
    }
    else {
        skipped.push(".proofwork/install.json");
    }
    writeIfMissing(path.join(root, "proofwork.config.json"), CONFIG, created, skipped, "proofwork.config.json");
    writeIfMissing(path.join(root, ".proofwork", "policy.json"), POLICY, created, skipped, ".proofwork/policy.json");
    const cliHelper = resolveCliSnippet();
    const sessionHook = `${cliHelper}
const r = runProofwork(["status"]);
process.stdout.write(JSON.stringify({ additional_context: (r.stdout || "proofwork status unavailable").trim().slice(0, 800) }));
`;
    const afterShell = `${cliHelper}
let raw = "";
try { raw = fs.readFileSync(0, "utf8"); } catch { raw = ""; }
let exit = 0, command = "";
try { const j = JSON.parse(raw || "{}"); exit = Number(j.exit_code ?? j.exitCode ?? 0); command = String(j.command || j.cmd || ""); } catch {}
if (exit === 0) { process.stdout.write("{}"); process.exit(0); }
runProofwork(["ledger", "add", "--type", "failure", "--name", command || "shell", "--detail", "exit " + exit, "--fingerprint", command || "shell"]);
process.stdout.write(JSON.stringify({ additional_context: "Proofwork ledger: recorded failed shell (exit " + exit + ")" }));
`;
    const stopHook = `${cliHelper}
const r = runProofwork(["status"]);
const ok = r.status === 0;
const brief = (r.stdout || "").trim().slice(0, 1200);
process.stdout.write(JSON.stringify(ok ? { additional_context: "Proofwork stop: " + brief } : { agent_message: "Proofwork FAILED — fix blockers.\\n" + brief }));
`;
    writeIfMissing(path.join(root, ".cursor", "hooks.json"), HOOKS_JSON, created, skipped, ".cursor/hooks.json");
    writeIfMissing(path.join(root, ".cursor", "hooks", "proofwork-session.mjs"), sessionHook, created, skipped, ".cursor/hooks/proofwork-session.mjs");
    writeIfMissing(path.join(root, ".cursor", "hooks", "proofwork-after-shell.mjs"), afterShell, created, skipped, ".cursor/hooks/proofwork-after-shell.mjs");
    writeIfMissing(path.join(root, ".cursor", "hooks", "proofwork-stop.mjs"), stopHook, created, skipped, ".cursor/hooks/proofwork-stop.mjs");
    writeIfMissing(path.join(root, ".cursor", "mcp.json"), MCP_JSON, created, skipped, ".cursor/mcp.json");
    writeIfMissing(path.join(root, ".cursor", "run-proofwork-mcp.mjs"), MCP_LAUNCHER, created, skipped, ".cursor/run-proofwork-mcp.mjs");
    const agentsMd = [
        "# Agent contract — Proofwork",
        "",
        "Before claiming done: run `proofwork status` (or MCP `proofwork_status`).",
        "On FAIL: fix blockers / `proofwork doctor` — do not declare completion.",
        "On failed shells: ledger via hook or `proofwork ledger add`.",
        "Do not fake-green (skip / .only / empty / weak asserts) or reintroduce deleted code.",
        "Delivery acceptance: `proofwork accept` must stay green after install.",
        "",
    ].join("\n");
    const ruleMdc = [
        "---",
        "description: Proofwork Proof of Work gate",
        "alwaysApply: true",
        "---",
        "",
        "Before claiming done, run `proofwork status`. On FAIL, fix blockers — do not declare completion.",
        "Prefer MCP `proofwork_status` / `proofwork_doctor`. See AGENTS.md.",
        "",
    ].join("\n");
    writeIfMissing(path.join(root, "AGENTS.md"), agentsMd, created, skipped, "AGENTS.md");
    writeIfMissing(path.join(root, ".cursor", "rules", "proofwork.mdc"), ruleMdc, created, skipped, ".cursor/rules/proofwork.mdc");
    return { created, skipped };
}
