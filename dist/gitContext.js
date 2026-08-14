import fs from "node:fs";
import path from "node:path";
import { tryExec } from "./util/exec.js";
function addNames(set, block) {
    for (const line of block.split(/\r?\n/)) {
        const t = line.trim();
        if (t)
            set.add(t.replace(/\\/g, "/"));
    }
}
function collectChangedFiles(root) {
    const set = new Set();
    const base = process.env.GITHUB_BASE_REF;
    if (base) {
        const pr = tryExec("git", ["diff", "--name-only", `origin/${base}...HEAD`], root, 8_000);
        if (pr.ok)
            addNames(set, pr.out);
    }
    const porcelain = tryExec("git", ["status", "--porcelain", "-uall"], root, 8_000);
    if (porcelain.ok && porcelain.out.length) {
        for (const line of porcelain.out.split(/\r?\n/)) {
            if (line.length < 4)
                continue;
            const rest = line.slice(3);
            const arrow = rest.indexOf(" -> ");
            const file = (arrow === -1 ? rest : rest.slice(arrow + 4)).trim().replace(/\\/g, "/");
            if (file)
                set.add(file);
        }
    }
    else {
        const unstaged = tryExec("git", ["diff", "--name-only", "HEAD"], root, 8_000);
        const staged = tryExec("git", ["diff", "--cached", "--name-only"], root, 8_000);
        const untracked = tryExec("git", ["ls-files", "--others", "--exclude-standard"], root, 8_000);
        for (const block of [unstaged.out, staged.out, untracked.out])
            addNames(set, block);
    }
    return [...set];
}
/** Untracked files are invisible to `git diff` — synthesize add hunks for reintro. */
function synthesizeUntrackedDiff(root, changedFiles) {
    const parts = [];
    let budget = 0;
    for (const rel of changedFiles) {
        if (budget >= 40)
            break;
        const norm = rel.replace(/\\/g, "/");
        if (norm.startsWith(".proofwork/") || norm.includes("/node_modules/"))
            continue;
        const tracked = tryExec("git", ["ls-files", "--error-unmatch", "--", rel], root, 2_000);
        if (tracked.ok)
            continue;
        const abs = path.join(root, rel);
        if (!fs.existsSync(abs) || !fs.statSync(abs).isFile())
            continue;
        let text = "";
        try {
            text = fs.readFileSync(abs, "utf8");
        }
        catch {
            continue;
        }
        if (text.length > 120_000)
            continue;
        const lines = text.split(/\r?\n/);
        parts.push(`diff --git a/${norm} b/${norm}`);
        parts.push("--- /dev/null");
        parts.push(`+++ b/${norm}`);
        parts.push(`@@ -0,0 +1,${Math.max(lines.length, 1)} @@`);
        for (const line of lines)
            parts.push(`+${line}`);
        budget += 1;
    }
    return parts.join("\n");
}
function collectUnifiedDiff(root, changedFiles) {
    const base = process.env.GITHUB_BASE_REF;
    if (base) {
        const merge = tryExec("git", ["diff", "--unified=0", `origin/${base}...HEAD`], root, 12_000);
        if (merge.ok && merge.out.trim()) {
            const syn = synthesizeUntrackedDiff(root, changedFiles);
            return syn ? `${merge.out}\n${syn}` : merge.out;
        }
        const merge2 = tryExec("git", ["diff", "--unified=0", `${base}...HEAD`], root, 12_000);
        if (merge2.ok && merge2.out.trim()) {
            const syn = synthesizeUntrackedDiff(root, changedFiles);
            return syn ? `${merge2.out}\n${syn}` : merge2.out;
        }
    }
    const staged = tryExec("git", ["diff", "--cached", "--unified=0"], root, 8_000);
    const unstaged = tryExec("git", ["diff", "--unified=0"], root, 8_000);
    const local = [staged.ok ? staged.out : "", unstaged.ok ? unstaged.out : ""]
        .filter(Boolean)
        .join("\n");
    const syn = synthesizeUntrackedDiff(root, changedFiles);
    if (local.trim() || syn) {
        return [local, syn].filter((s) => s.trim()).join("\n");
    }
    const againstMain = tryExec("git", ["diff", "--unified=0", "origin/main...HEAD"], root, 12_000);
    if (againstMain.ok && againstMain.out.trim())
        return againstMain.out;
    return "";
}
export function buildGitContext(root) {
    const t0 = performance.now();
    const gitDir = path.join(root, ".git");
    const isGit = fs.existsSync(gitDir);
    if (!isGit) {
        return {
            root,
            isGit: false,
            branch: null,
            commit: null,
            changedFiles: [],
            unifiedDiff: "",
            git_ms: Math.round(performance.now() - t0),
        };
    }
    const branch = tryExec("git", ["rev-parse", "--abbrev-ref", "HEAD"], root, 5_000);
    const commit = tryExec("git", ["rev-parse", "HEAD"], root, 5_000);
    const changedFiles = collectChangedFiles(root);
    const unifiedDiff = collectUnifiedDiff(root, changedFiles);
    return {
        root,
        isGit: true,
        branch: branch.ok ? branch.out : null,
        commit: commit.ok ? commit.out : null,
        changedFiles,
        unifiedDiff,
        git_ms: Math.round(performance.now() - t0),
    };
}
