import fs from "node:fs";
import path from "node:path";
import { tryExec } from "./util/exec.js";
/**
 * Where the repository actually is, relative to the directory being graded.
 *
 * A checkout does not stop being a checkout because you point at a subdirectory
 * of it. Git resolves this by walking up until it finds `.git`, and grading
 * `packages/api` of a monorepo has to behave the same way — otherwise
 * `git.repository` fails on a directory that is plainly inside a clone, the
 * proof is not `ok`, and a run that deserves a certificate never gets one.
 *
 * `.git` is tested with `existsSync` rather than `isDirectory` on purpose: in a
 * worktree or a submodule it is a *file* containing a `gitdir:` pointer.
 */
function findRepoRoot(start) {
    let dir = path.resolve(start);
    for (;;) {
        if (fs.existsSync(path.join(dir, ".git")))
            return dir;
        const parent = path.dirname(dir);
        if (parent === dir)
            return null;
        dir = parent;
    }
}
/** `packages/api/` when grading a subdirectory, `""` at the repository root. */
function prefixFor(repoRoot, root) {
    const rel = path.relative(repoRoot, path.resolve(root)).replace(/\\/g, "/");
    return rel && rel !== "." ? `${rel}/` : "";
}
function addNames(set, block) {
    for (const line of block.split(/\r?\n/)) {
        const t = line.trim();
        if (t)
            set.add(t.replace(/\\/g, "/"));
    }
}
/**
 * Re-base paths git reported from the repository root onto the graded root.
 *
 * Measured rather than assumed, because git is not consistent about it:
 * `git status --porcelain` reports from the repository root even when run in a
 * subdirectory and even when scoped to `.`, while `git ls-files --others`
 * reports from the current directory. Mixing the two under a subdirectory root
 * produces paths like `packages/api/packages/api/src/x.ts`, and every check that
 * opens a changed file then silently finds nothing.
 *
 * Files outside the graded directory are dropped rather than re-based. They
 * belong to a sibling package, and grading a directory must not draw conclusions
 * from code that is not in it — that is what made the last attempt read a
 * neighbouring app's empty test as if it were the subject's.
 */
function rebase(files, prefix) {
    if (!prefix)
        return [...files];
    const out = [];
    for (const f of files) {
        if (f.startsWith(prefix))
            out.push(f.slice(prefix.length));
    }
    return out;
}
function collectChangedFiles(root, prefix) {
    /** Reported relative to the repository root; needs re-basing. */
    const fromRepoRoot = new Set();
    /** Already relative to the graded directory. */
    const fromHere = new Set();
    const base = process.env.GITHUB_BASE_REF;
    if (base) {
        const pr = tryExec("git", ["diff", "--name-only", `origin/${base}...HEAD`], root, 8_000);
        if (pr.ok)
            addNames(fromRepoRoot, pr.out);
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
                fromRepoRoot.add(file);
        }
    }
    else {
        const unstaged = tryExec("git", ["diff", "--name-only", "HEAD"], root, 8_000);
        const staged = tryExec("git", ["diff", "--cached", "--name-only"], root, 8_000);
        for (const block of [unstaged.out, staged.out])
            addNames(fromRepoRoot, block);
        const untracked = tryExec("git", ["ls-files", "--others", "--exclude-standard"], root, 8_000);
        addNames(fromHere, untracked.out);
    }
    return [...new Set([...rebase(fromRepoRoot, prefix), ...fromHere])];
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
        const merge = tryExec("git", ["diff", "--relative", "--unified=0", `origin/${base}...HEAD`], root, 12_000);
        if (merge.ok && merge.out.trim()) {
            const syn = synthesizeUntrackedDiff(root, changedFiles);
            return syn ? `${merge.out}\n${syn}` : merge.out;
        }
        const merge2 = tryExec("git", ["diff", "--relative", "--unified=0", `${base}...HEAD`], root, 12_000);
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
    // Walk up, exactly as git does. A subdirectory of a clone is still in that
    // clone, and treating it otherwise failed `git.repository` for every monorepo
    // package — which made `proof.ok` false while the report card still read
    // CERTIFIED, so CI exited 2 and no record was ever deposited for work that had
    // earned one.
    const repoRoot = findRepoRoot(root);
    const isGit = repoRoot !== null;
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
    const prefix = prefixFor(repoRoot, root);
    const branch = tryExec("git", ["rev-parse", "--abbrev-ref", "HEAD"], root, 5_000);
    const commit = tryExec("git", ["rev-parse", "HEAD"], root, 5_000);
    const changedFiles = collectChangedFiles(root, prefix);
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
