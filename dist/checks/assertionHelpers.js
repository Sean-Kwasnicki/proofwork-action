/**
 * Assertions that live in a helper the test calls, not in the `it()` body.
 *
 * An agent that read the hollow detector puts `expect(true).toBe(true)` in
 * `test/helpers.js` and writes `it("charges", () => assertCharged(res))`.
 * Scanning only the `it()` body then either:
 *   - flags honest helper-style tests as hollow, or
 *   - misses theater that was moved one file over.
 *
 * Both are the same bug: the verdict asked the wrong file. Relative imports
 * and same-file functions are followed. Production `src/` is not, because
 * that is the code under test, not a test helper.
 *
 * No TypeScript. Brace walk only. Depth-capped so a cycle cannot hang the gate.
 */
import fs from "node:fs";
import path from "node:path";
import { extractTests, bodyLooksEmpty } from "./extractTests.js";
import { findAssertions, judgeTest } from "./assertionQuality.js";
import { isTestPath } from "./testPaths.js";
const MAX_HELPERS = 8;
const MAX_BYTES = 80 * 1024;
export function isHelperPath(rel) {
    const norm = rel.replace(/\\/g, "/");
    const base = norm.slice(norm.lastIndexOf("/") + 1);
    if (isTestPath(norm))
        return true;
    return /helper|assert|test-utils|testUtils|specHelper|testHelper/i.test(base);
}
function escapeRe(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
export function namedCallsIn(body, names) {
    const hit = [];
    for (const name of names) {
        const re = new RegExp(`\\b${escapeRe(name)}\\s*\\(`);
        if (re.test(body))
            hit.push(name);
    }
    return hit;
}
export function extractFunctionBody(source, name) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const starters = [
        new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${escaped}\\s*\\(`),
        new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s*)?(?:function\\s*)?\\(`),
        new RegExp(`${escaped}\\s*:\\s*(?:async\\s*)?(?:function\\s*)?\\(`),
    ];
    let start = -1;
    for (const re of starters) {
        const m = re.exec(source);
        if (m) {
            start = m.index + m[0].length;
            break;
        }
    }
    if (start < 0)
        return null;
    const brace = source.indexOf("{", start);
    if (brace < 0 || brace - start > 200)
        return null;
    let depth = 0;
    let body = "";
    for (let i = brace; i < source.length && i < brace + 20_000; i += 1) {
        const ch = source[i];
        if (ch === "{") {
            depth += 1;
            if (depth === 1)
                continue;
        }
        else if (ch === "}") {
            depth -= 1;
            if (depth === 0)
                return body;
        }
        if (depth >= 1)
            body += ch;
    }
    return null;
}
export function relativeImports(text) {
    const out = [];
    const esm = /\bimport\s+(?:type\s+)?(?:\{([^}]+)\}|\*\s+as\s+(\w+)|(\w+))\s+from\s+['"](\.[^'"]+)['"]/g;
    let m;
    while ((m = esm.exec(text))) {
        const names = m[1]
            ? m[1]
                .split(",")
                .map((p) => p.trim().split(/\s+as\s+/).pop().trim())
                .filter(Boolean)
            : [m[2] || m[3]].filter((n) => Boolean(n));
        out.push({ names, spec: m[4] });
    }
    const cjs = /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
    while ((m = cjs.exec(text))) {
        const names = m[1]
            .split(",")
            .map((p) => p.trim().split(/\s*:\s*/).pop().trim())
            .filter(Boolean);
        out.push({ names, spec: m[2] });
    }
    return out;
}
function resolveHelper(fromFile, spec, files, root) {
    const fromDir = path.posix.dirname(fromFile.replace(/\\/g, "/"));
    const joined = path.posix.normalize(`${fromDir}/${spec}`).replace(/^\.\//, "");
    const candidates = [
        joined,
        `${joined}.js`,
        `${joined}.ts`,
        `${joined}.mjs`,
        `${joined}.cjs`,
        `${joined}/index.js`,
    ];
    for (const rel of candidates) {
        if (!isHelperPath(rel))
            continue;
        if (files && files[rel] !== undefined)
            return { rel, text: files[rel] };
        if (root) {
            const abs = path.join(root, rel);
            try {
                if (fs.existsSync(abs) && fs.statSync(abs).isFile() && fs.statSync(abs).size <= MAX_BYTES) {
                    return { rel, text: fs.readFileSync(abs, "utf8") };
                }
            }
            catch {
                /* unreadable */
            }
        }
    }
    return null;
}
/**
 * Assertions a test body reaches by calling a helper, including helpers
 * declared in the same file.
 */
export function assertionsViaHelpers(fileText, testBody, opts = {}) {
    const found = [];
    const localNames = new Set();
    const fn = /(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;
    const cn = /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\(/g;
    let m;
    while ((m = fn.exec(fileText)))
        localNames.add(m[1]);
    while ((m = cn.exec(fileText)))
        localNames.add(m[1]);
    for (const name of namedCallsIn(testBody, localNames)) {
        const body = extractFunctionBody(fileText, name);
        if (body)
            found.push(...findAssertions(body));
    }
    if (!opts.file)
        return found.slice(0, 80);
    let walked = 0;
    for (const imp of relativeImports(fileText)) {
        if (walked >= MAX_HELPERS)
            break;
        const called = namedCallsIn(testBody, imp.names);
        if (called.length === 0)
            continue;
        const resolved = resolveHelper(opts.file, imp.spec, opts.files, opts.root);
        if (!resolved)
            continue;
        walked += 1;
        for (const name of called) {
            const body = extractFunctionBody(resolved.text, name);
            if (body)
                found.push(...findAssertions(body));
        }
    }
    return found.slice(0, 80);
}
export function assertionsForTestBody(fileText, testBody, opts = {}) {
    return [...findAssertions(testBody), ...assertionsViaHelpers(fileText, testBody, opts)];
}
export function fileHasConstrainingAssertionDeep(text, opts = {}) {
    for (const t of extractTests(text)) {
        if (bodyLooksEmpty(t.body))
            continue;
        if (judgeTest(assertionsForTestBody(text, t.body, opts), false).constraining > 0)
            return true;
    }
    // A helper module with no `it()` still constrains if it asserts.
    if (extractTests(text).length === 0) {
        return judgeTest(findAssertions(text), false).constraining > 0;
    }
    return false;
}
