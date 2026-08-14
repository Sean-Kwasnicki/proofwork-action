import fs from "node:fs";
import path from "node:path";
import { runProof } from "./run.js";
import { scoreProof } from "./scoring.js";
import { buildReportCard } from "./reportCard.js";
/** Directories that are agent repositories rather than incidental folders. */
function looksLikeRepo(dir) {
    return (fs.existsSync(path.join(dir, "package.json")) ||
        fs.existsSync(path.join(dir, ".git")) ||
        fs.existsSync(path.join(dir, "pyproject.toml")) ||
        fs.existsSync(path.join(dir, "go.mod")));
}
/**
 * Grade every agent under a directory.
 *
 * Read-only throughout: fleet review is something an operator does to code they
 * may not own, often on a schedule, and a weekly report that dirties forty
 * working trees would be removed after its first run.
 */
export function reviewFleet(root, opts = {}) {
    const previousReadOnly = process.env.PROOFWORK_READONLY;
    process.env.PROOFWORK_READONLY = "1";
    const members = [];
    let entries = [];
    try {
        entries = fs.readdirSync(root, { withFileTypes: true });
    }
    catch {
        entries = [];
    }
    for (const e of entries) {
        if (!e.isDirectory() || e.name.startsWith(".") || e.name === "node_modules")
            continue;
        const dir = path.join(root, e.name);
        if (!looksLikeRepo(dir))
            continue;
        try {
            const proof = runProof({ root: dir, fast: opts.fast ?? true });
            const score = scoreProof(proof);
            const card = buildReportCard(proof, e.name);
            const failing = proof.checks.filter((c) => c.status === "fail").map((c) => c.id);
            const reasons = card.categories.filter((c) => c.status === "failed").flatMap((c) => c.lost_because);
            members.push({
                name: e.name,
                root: dir,
                ok: proof.ok,
                score: score.final,
                band: score.band,
                failing,
                reasons: [...new Set(reasons)],
                notExamined: proof.checks.filter((c) => c.status === "skip").length,
            });
        }
        catch (err) {
            // A repository the gate cannot process is reported, never skipped. Silently
            // dropping it would shrink the denominator and inflate the pass rate.
            members.push({
                name: e.name,
                root: dir,
                ok: false,
                score: 0,
                band: "error",
                failing: [],
                reasons: [],
                notExamined: 0,
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }
    if (previousReadOnly === undefined)
        delete process.env.PROOFWORK_READONLY;
    else
        process.env.PROOFWORK_READONLY = previousReadOnly;
    // Worst first. A list sorted alphabetically buries the agent that matters
    // behind whichever one happens to start with "a".
    members.sort((a, b) => a.score - b.score);
    /**
     * Grouped by what the operator would *do*, not by check id.
     *
     * Several check ids resolve to the same customer-facing sentence, so keying on
     * the id printed the same line twice with the counts split between them —
     * which understates how widespread the problem is and reads like a rendering
     * fault. The reason is what a reader acts on, so the reason is the key, and the
     * ids that produced it are kept alongside for anyone who wants them.
     */
    const counts = new Map();
    for (const m of members) {
        // One vote per agent per distinct reason: an agent failing two checks that
        // mean the same thing is still one agent with that problem.
        const seen = new Set();
        for (const id of m.failing) {
            const reason = m.reasons[0] ?? id;
            if (seen.has(reason))
                continue;
            seen.add(reason);
            const prior = counts.get(reason);
            counts.set(reason, {
                count: (prior?.count ?? 0) + 1,
                ids: new Set([...(prior?.ids ?? []), id]),
            });
        }
    }
    return {
        scanned: members.length,
        certified: members.filter((m) => m.ok).length,
        denied: members.filter((m) => !m.ok && m.band !== "error").length,
        provisional: members.filter((m) => m.band === "provisional").length,
        errored: members.filter((m) => m.band === "error").length,
        members,
        commonFailures: [...counts.entries()]
            .map(([reason, v]) => ({ id: [...v.ids].join(", "), count: v.count, reason }))
            .sort((a, b) => b.count - a.count),
    };
}
/** Rendered for whoever has to sign off on the fleet. */
export function renderFleet(f) {
    const rule = "─".repeat(78);
    if (f.scanned === 0) {
        return [
            "",
            "  FLEET REVIEW",
            `  ${rule}`,
            "",
            "  No agent repositories found. Point this at a directory whose children are",
            "  repositories — each needs a package.json, .git, pyproject.toml, or go.mod.",
            "",
        ].join("\n");
    }
    const out = [
        "",
        "  FLEET REVIEW",
        `  ${rule}`,
        "",
        `  ${f.scanned} agents · ${f.certified} certified · ${f.denied} denied` +
            (f.errored ? ` · ${f.errored} could not be graded` : ""),
        "",
        `  ${rule}`,
        "",
    ];
    for (const m of f.members) {
        const state = m.band === "error" ? "ERROR" : m.ok ? "CERTIFIED" : "DENIED";
        out.push(`  ${state.padEnd(10)} ${m.name.padEnd(26).slice(0, 26)} ${String(m.score).padStart(3)}/100`);
        if (m.error)
            out.push(`  ${" ".repeat(10)} ${m.error.slice(0, 70)}`);
        for (const r of m.reasons.slice(0, 2))
            out.push(`  ${" ".repeat(10)} · ${r.slice(0, 76)}`);
    }
    if (f.commonFailures.length > 0) {
        out.push("", `  ${rule}`, "", "  MOST COMMON ACROSS THE FLEET", "");
        for (const c of f.commonFailures.slice(0, 5)) {
            const noun = c.count === 1 ? "agent " : "agents";
            out.push(`  ${String(c.count).padStart(3)} ${noun}   ${c.reason || c.id}`);
        }
        out.push("");
        out.push("  Fixing the top row once usually fixes it everywhere — these are");
        out.push("  normally one shared template or one copied module.");
    }
    out.push("", `  ${rule}`, "", "  A fleet has no combined score, deliberately. Averaging would let clean", "  agents bury the one that can move money without asking.", "");
    return out.join("\n");
}
