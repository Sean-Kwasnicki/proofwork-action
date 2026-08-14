import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { loadConfig } from "./config.js";
import { runProof } from "./run.js";
function exists(root, rel) {
    return fs.existsSync(path.join(root, rel));
}
function readJson(root, rel) {
    const p = path.join(root, rel);
    if (!fs.existsSync(p))
        return null;
    try {
        return JSON.parse(fs.readFileSync(p, "utf8"));
    }
    catch {
        return null;
    }
}
/** Max-capacity customer acceptance — install is not done until this passes. */
export function runAccept(root) {
    const items = [];
    const push = (id, ok, detail) => items.push({ id, ok, detail });
    const config = loadConfig(root);
    push("config.strictIntegrity", config.strictIntegrity === true, config.strictIntegrity
        ? "strictIntegrity enabled (soft fake-green → FAIL)"
        : "strictIntegrity must be true for paid installs");
    push("config.failOnWarn", config.failOnWarn === true, config.failOnWarn ? "failOnWarn enabled" : "failOnWarn must be true for paid installs");
    push("config.maxIdenticalFailures", (config.maxIdenticalFailures ?? 99) <= 2, `maxIdenticalFailures=${config.maxIdenticalFailures ?? "default"} (required ≤ 2)`);
    push("scaffold.workflow", exists(root, ".github/workflows/proofwork.yml"), "GitHub Action workflow");
    push("scaffold.policy", exists(root, ".proofwork/policy.json"), "Base-pinnable grader policy (.proofwork/policy.json)");
    push("scaffold.hooks_json", exists(root, ".cursor/hooks.json"), "Cursor hooks.json");
    const hookSession = exists(root, ".cursor/hooks/proofwork-session.mjs") ||
        exists(root, ".cursor/hooks/session-start.mjs");
    const hookShell = exists(root, ".cursor/hooks/proofwork-after-shell.mjs") ||
        exists(root, ".cursor/hooks/after-shell.mjs");
    const hookStop = exists(root, ".cursor/hooks/proofwork-stop.mjs") || exists(root, ".cursor/hooks/stop-check.mjs");
    push("scaffold.hook_session", hookSession, "sessionStart hook");
    push("scaffold.hook_shell", hookShell, "afterShellExecution ledger hook");
    push("scaffold.hook_stop", hookStop, "stop gate hook");
    push("scaffold.agents", exists(root, "AGENTS.md"), "AGENTS.md agent contract");
    push("scaffold.rule", exists(root, ".cursor/rules/proofwork.mdc"), "Cursor always-apply rule");
    const mcp = readJson(root, ".cursor/mcp.json");
    const hasMcp = Boolean(mcp?.mcpServers?.proofwork?.command) || exists(root, ".cursor/run-proofwork-mcp.mjs");
    push("scaffold.mcp", hasMcp, "MCP server entry (proofwork_status tools)");
    const install = readJson(root, ".proofwork/install.json");
    const home = process.env.PROOFWORK_HOME || install?.proofwork_home || "";
    const homeOk = Boolean(home && fs.existsSync(path.join(String(home), "dist", "cli.js")));
    const selfEngine = exists(root, "dist/cli.js") &&
        (() => {
            try {
                const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
                return pkg.name === "proofwork";
            }
            catch {
                return false;
            }
        })();
    const linked = spawnSync(process.platform === "win32" ? "where" : "which", ["proofwork"], { encoding: "utf8" });
    const onPath = linked.status === 0;
    push("runtime.cli", homeOk || onPath || selfEngine, homeOk
        ? `PROOFWORK_HOME → ${home}`
        : selfEngine
            ? "Engine repo (dist/cli.js present)"
            : onPath
                ? "proofwork binary on PATH (npm link)"
                : "Set PROOFWORK_HOME or run scripts/install-into.mjs --target <app>");
    // Live Proof at max bar
    const proof = runProof({ root, fast: true, strict: true });
    push("proof.live", proof.ok, proof.ok
        ? `Proof PASS score=${proof.integrity_score ?? "?"}`
        : `Proof FAIL — ${proof.blockers.slice(0, 3).join("; ") || "see proofwork doctor"}`);
    const report = {
        ok: items.every((i) => i.ok),
        root,
        created_at: new Date().toISOString(),
        items,
        proof_ok: proof.ok,
        integrity_score: proof.integrity_score,
    };
    const outDir = path.join(root, ".proofwork");
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "ACCEPTANCE.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    return report;
}
