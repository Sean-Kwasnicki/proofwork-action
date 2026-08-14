import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { computeTreeBinding } from "./binding.js";
/**
 * A binding digest that carries no information about the tree.
 *
 * `computeTreeBinding` reports "no git here" by returning a *sentinel string*
 * rather than null — `unbound:not-a-git-repo`. A nullish check therefore never
 * fires, and the sentinel is byte-identical for every non-git repository on
 * earth. Sealing against it compared a constant to itself: the seal always held,
 * so tamper detection was silently off for exactly the first-time users who have
 * not run `git init` yet.
 *
 * Any `unbound:` digest is treated as no digest at all.
 */
const isUnbound = (digest) => !digest || digest.startsWith("unbound:");
/** Take a seal over the tree. */
export function takeSeal(root) {
    const binding = computeTreeBinding(root);
    const bound = !isUnbound(binding?.tree_digest);
    return {
        tree_digest: bound ? binding.tree_digest : emptyDigest(root),
        commit: binding?.commit ?? null,
        files: bound ? (binding?.file_count ?? 0) : countFiles(root),
        at: new Date().toISOString(),
    };
}
/**
 * Fallback digest for a tree with no git binding.
 *
 * A repository without git still deserves a sealed run — most first-time users
 * have one — so the absence of a commit cannot mean the absence of a seal.
 */
const SKIP = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out",
    "coverage", "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
/** File entries as `path:size:mtime`, sorted. Shared by the digest and the count. */
function treeEntries(root, max = 2000) {
    const stack = [root];
    const seen = [];
    while (stack.length && seen.length < max) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            const abs = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (!SKIP.has(e.name))
                    stack.push(abs);
                continue;
            }
            try {
                const st = fs.statSync(abs);
                seen.push(`${path.relative(root, abs).replace(/\\/g, "/")}:${st.size}:${st.mtimeMs}`);
            }
            catch {
                // A file that vanished mid-walk is itself movement; the closing seal
                // will differ, which is the correct outcome.
            }
        }
    }
    // Sorted so the digest depends on the tree's contents rather than on the order
    // the filesystem happened to return entries in. Without this, two seals over an
    // unchanged tree could differ and every run would be reported void.
    return seen.sort();
}
function countFiles(root) {
    return treeEntries(root).length;
}
function emptyDigest(root) {
    const h = crypto.createHash("sha256");
    const seen = treeEntries(root);
    for (const line of seen)
        h.update(`${line}\n`);
    return h.digest("hex");
}
/**
 * Run `body` between two seals.
 *
 * The result is returned alongside the verdict rather than thrown away when the
 * seal breaks, because a void run's findings are still worth showing to the
 * person who ran it — they simply cannot be certified or written to the registry.
 */
export function runSealed(root, body) {
    const started = Date.now();
    const open = takeSeal(root);
    const result = body();
    const close = takeSeal(root);
    const duration_ms = Date.now() - started;
    if (open.tree_digest === close.tree_digest) {
        return { result, verdict: { sealed: true, open, close, duration_ms } };
    }
    const movedFiles = close.files - open.files;
    const reason = movedFiles !== 0
        ? `The repository changed while it was being graded: ${Math.abs(movedFiles)} file(s) were ` +
            `${movedFiles > 0 ? "added" : "removed"} between the opening and closing seal.`
        : "The repository changed while it was being graded: file contents differ between the " +
            "opening and closing seal.";
    return { result, verdict: { sealed: false, open, close, duration_ms, reason } };
}
/** Rendered for a human. Says void, never failed — they are different claims. */
export function describeSeal(v) {
    if (v.sealed) {
        return (`Sealed run — the repository was identical before and after grading ` +
            `(${v.open.files} files, ${v.duration_ms}ms, digest ${v.open.tree_digest.slice(0, 12)}…).`);
    }
    return [
        `VOID — this run cannot be certified.`,
        ``,
        `  ${v.reason}`,
        ``,
        `  Opened  ${v.open.at}  ${v.open.tree_digest.slice(0, 16)}…`,
        `  Closed  ${v.close.at}  ${v.close.tree_digest.slice(0, 16)}…`,
        ``,
        `  A void run is not a failing run. It makes no claim about the agent at all —`,
        `  the verdict describes a repository that did not exist at any single moment.`,
        `  Re-run with nothing else writing to the working tree.`,
    ].join("\n");
}
