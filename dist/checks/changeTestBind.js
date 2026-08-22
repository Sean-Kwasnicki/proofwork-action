/**
 * Diff → test bind. Does not run the suite.
 *
 * Substantial production hunk (≥4 non-noise added lines). Each changed
 * source file must be imported, or an export named, in a test file that
 * has a constraining assertion.
 *
 * On incorporate: `src/checks/changeTestBind.ts`, check id
 * `integrity.change_test_bind`. Use Cursor_B `isNoiseLine` / `isTestPath` /
 * `isSourcePath` / `isUnderForeignTree` instead of the copies below.
 */
import { fileHasConstrainingAssertionDeep } from "./assertionHelpers.js";
import { isNoiseLine } from "./reintroduction.js";
import { isSourcePath, isTestPath, isUnderForeignTree, WALK_SKIP_DIRS } from "./testPaths.js";
import { buildGitContext } from "../gitContext.js";
import fs from "node:fs";
import path from "node:path";
export const SUBSTANTIAL_ADDED_LINES = 4;
export function isDocsPath(p) {
    const f = p.replace(/\\/g, "/");
    const ext = f.includes(".") ? f.slice(f.lastIndexOf(".")).toLowerCase() : "";
    return (ext === ".md" ||
        ext === ".html" ||
        ext === ".css" ||
        f.endsWith("package-lock.json") ||
        f.startsWith("docs/") ||
        f.startsWith(".cursor/") ||
        f.startsWith(".github/") ||
        f.startsWith(".proofwork/"));
}
/** Minimal unified-diff parser (git diff / GitHub patch). */
export function parseUnifiedDiff(diff) {
    const files = [];
    let current = null;
    for (const raw of diff.split(/\r?\n/)) {
        const git = /^diff --git a\/(.+?) b\/(.+)$/.exec(raw);
        if (git) {
            current = { path: git[2], added: [], deleted: [] };
            files.push(current);
            continue;
        }
        const plusName = /^\+\+\+ b\/(.+)$/.exec(raw);
        if (plusName && current)
            current.path = plusName[1];
        if (!current)
            continue;
        if (raw.startsWith("+++") || raw.startsWith("---") || raw.startsWith("@@"))
            continue;
        if (raw.startsWith("+"))
            current.added.push(raw.slice(1));
        else if (raw.startsWith("-"))
            current.deleted.push(raw.slice(1));
    }
    return files;
}
export function extractExports(source) {
    const names = new Set();
    const patterns = [
        /\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexport\s+(?:async\s+)?function\s*\*\s*([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexport\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexport\s+const\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexport\s+let\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexport\s+default\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bexports\.([A-Za-z_$][A-Za-z0-9_$]*)/g,
        /\bmodule\.exports\.([A-Za-z_$][A-Za-z0-9_$]*)/g,
    ];
    for (const re of patterns) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(source)))
            names.add(m[1]);
    }
    const listed = /(?:module\.)?exports\s*=\s*\{([^}]+)\}/.exec(source);
    if (listed) {
        for (const part of listed[1].split(",")) {
            const id = /([A-Za-z_$][A-Za-z0-9_$]*)/.exec(part.trim());
            if (id)
                names.add(id[1]);
        }
    }
    return [...names];
}
export function basename(p) {
    const norm = p.replace(/\\/g, "/");
    const base = norm.slice(norm.lastIndexOf("/") + 1);
    return base.replace(/\.[cm]?[jt]sx?$/, "").replace(/\.(py|go|rb|java|cs)$/, "");
}
function wordIn(text, name) {
    const re = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
    return re.test(text);
}
export function testBindsToFile(testText, sourcePath, exportNames, ctx) {
    const base = basename(sourcePath);
    const importHit = new RegExp(`from\\s+['"][^'"]*${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:\\.[cm]?[jt]sx?)?['"]`).test(testText) ||
        new RegExp(`require\\(\\s*['"][^'"]*${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(testText);
    const constraining = fileHasConstrainingAssertionDeep(testText, {
        file: ctx?.path,
        files: ctx?.files,
    });
    if (importHit && constraining)
        return "strong";
    const named = exportNames.some((n) => wordIn(testText, n));
    if (named && constraining && importHit)
        return "strong";
    if (named && constraining)
        return "weak";
    // Name only in a comment is not a bind — fileHasConstraining still looks at tests,
    // but a name in a comment with no constraining assert is none.
    return "none";
}
export function bindDiff(input) {
    const parsed = parseUnifiedDiff(input.diff);
    if (parsed.length === 0) {
        return { skip: true, skipReason: "no diff", unbound: [], ok: true };
    }
    const production = parsed.filter((f) => isSourcePath(f.path) && !isDocsPath(f.path));
    const substantial = production.filter((f) => {
        const added = f.added.filter((l) => !isNoiseLine(l)).length;
        return added >= SUBSTANTIAL_ADDED_LINES;
    });
    if (production.length === 0) {
        return { skip: true, skipReason: "docs or non-source only", unbound: [], ok: true };
    }
    const onlyDeletes = production.every((f) => f.added.filter((l) => !isNoiseLine(l)).length === 0);
    if (onlyDeletes) {
        return { skip: true, skipReason: "deletions only — reintroduction owns that", unbound: [], ok: true };
    }
    if (substantial.length === 0) {
        return { skip: true, skipReason: `below ${SUBSTANTIAL_ADDED_LINES} non-noise added lines`, unbound: [], ok: true };
    }
    const testEntries = Object.entries(input.files).filter(([p]) => isTestPath(p));
    const unbound = [];
    for (const file of substantial) {
        const source = input.files[file.path] ?? file.added.join("\n");
        const symbols = extractExports(source);
        let best = "none";
        for (const [testPath, text] of testEntries) {
            const hit = testBindsToFile(text, file.path, symbols, { path: testPath, files: input.files });
            if (hit === "strong") {
                best = "strong";
                break;
            }
            if (hit === "weak")
                best = "weak";
        }
        if (best === "none") {
            unbound.push({
                path: file.path,
                symbols,
                reason: `substantial change in ${file.path} has no test that imports it or names an export with a constraining assertion`,
            });
        }
    }
    return { skip: false, unbound, ok: unbound.length === 0 };
}
export function bindCheck(input) {
    const r = bindDiff(input);
    if (r.skip) {
        return {
            id: "integrity.change_test_bind",
            status: "skip",
            detail: r.skipReason ?? "not applicable",
        };
    }
    if (r.ok) {
        return {
            id: "integrity.change_test_bind",
            status: "pass",
            detail: "Every substantial production hunk is bound to a constraining test",
        };
    }
    return {
        id: "integrity.change_test_bind",
        status: "fail",
        detail: r.unbound.map((u) => u.reason).join("; "),
    };
}
function walkTestFiles(root, max = 400) {
    const out = [];
    const stack = [root];
    while (stack.length && out.length < max) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            if (out.length >= max)
                break;
            const abs = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (!WALK_SKIP_DIRS.has(e.name) && !isUnderForeignTree(root, path.relative(root, abs))) {
                    stack.push(abs);
                }
            }
            else {
                const rel = path.relative(root, abs).replace(/\\/g, "/");
                if (isTestPath(rel) && !isUnderForeignTree(root, rel))
                    out.push(rel);
            }
        }
    }
    return out;
}
function existsUnderRoot(root, rel) {
    const abs = path.resolve(root, rel);
    const base = path.resolve(root);
    if (abs !== base && !abs.startsWith(base + path.sep) && !abs.startsWith(`${base}/`)) {
        return false;
    }
    try {
        return fs.existsSync(abs) && fs.statSync(abs).isFile();
    }
    catch {
        return false;
    }
}
function scopedDiff(root, diff) {
    const kept = parseUnifiedDiff(diff).filter((f) => !isUnderForeignTree(root, f.path) && existsUnderRoot(root, f.path));
    return kept
        .map((f) => {
        const lines = [
            `diff --git a/${f.path} b/${f.path}`,
            `--- a/${f.path}`,
            `+++ b/${f.path}`,
            "@@",
            ...f.deleted.map((l) => `-${l}`),
            ...f.added.map((l) => `+${l}`),
        ];
        return lines.join("\n");
    })
        .join("\n");
}
export function runChangeTestBindChecks(root, git) {
    const ctx = git ?? buildGitContext(root);
    const files = {};
    const diff = scopedDiff(root, ctx.unifiedDiff);
    const want = new Set([
        ...parseUnifiedDiff(diff).map((f) => f.path),
        ...walkTestFiles(root),
    ]);
    for (const rel of want) {
        if (isUnderForeignTree(root, rel))
            continue;
        try {
            const abs = path.join(root, rel);
            if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
                files[rel] = fs.readFileSync(abs, "utf8");
            }
        }
        catch {
            /* unreadable */
        }
    }
    const result = bindCheck({ diff, files });
    return [
        {
            id: result.id,
            title: "Change bound to a constraining test",
            status: result.status,
            detail: result.detail,
            evidence: { mode: ctx.unifiedDiff ? "diff" : "none" },
        },
    ];
}
