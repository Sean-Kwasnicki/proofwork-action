import fs from "node:fs";
import path from "node:path";
import { isForeignTree } from "../testPaths.js";
/**
 * Shared scanning primitives for the regulatory checks.
 *
 * These three checks — disclosure, record-keeping, automated decisions — all ask
 * questions about the *whole application*, not about a diff. A transparency
 * obligation is not discharged by the last commit; it is a property of the system
 * as deployed. So each walks the tree rather than reading `changedFiles`, and the
 * walking is done once, here.
 *
 * ## A note on what these checks are, and are not
 *
 * They produce **evidence about a codebase**, not a legal determination. A rule
 * here can establish that no AI-disclosure string exists anywhere near an outbound
 * human channel. It cannot establish that a company is non-compliant with Article
 * 50, because compliance depends on facts outside the repository: who the users
 * are, what the deployment context is, whether disclosure happens in a UI layer
 * that lives in another service, and whether an exemption applies.
 *
 * Every message these checks emit is therefore worded as an observation about
 * code with a named regulatory reference attached — never as a compliance verdict.
 * A product that exists to catch overstated claims cannot be the thing that
 * overstates them.
 */
export const REG_SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork", ".cache",
]);
export const REG_MAX_BYTES = 512 * 1024;
const CODE_RE = /\.[cm]?[jt]sx?$|\.py$|\.rb$|\.go$|\.java$|\.cs$|\.php$/i;
const CONFIG_RE = /\.(json|ya?ml|toml|env|ini)$/i;
const DOC_RE = /\.(md|mdx|txt|html?)$/i;
/**
 * Files that demonstrate a pattern rather than commit it.
 *
 * Security fixtures, documentation examples, and test data routinely contain the
 * exact strings these rules search for. Treating them as live findings is how a
 * gate accuses the security team that installed it — a mistake this project has
 * already shipped once and will not ship again.
 */
export const isTestOrFixture = (rel) => /(^|\/)(?:__tests__|__mocks__|testdata|fixtures?|examples?|samples?|demos?|docs?)\//i.test(rel) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(rel) ||
    /(^|\/)(?:test|tests|spec|e2e)\//i.test(rel) ||
    // Filenames, not only directories. This project's own `scripts/demo-report-card.mjs`
    // holds fixture agents with a 7-day retention value in them, and the check read
    // it as live configuration — a directory-only matcher misses every
    // `seed-data.js`, `example-agent.mjs`, and `mock-config.json` a customer has.
    /(^|\/)(?:demo|example|sample|fixture|seed|mock|scaffold)[-_.]/i.test(rel) ||
    /[-_.](?:demo|example|sample|fixture|seed|mock)\.[cm]?[jt]sx?$/i.test(rel);
/** Read every relevant file once. Callers filter; nobody walks the tree twice. */
export function scanTree(root, max = 800) {
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
                // A directory that is — or holds — other repositories belongs to another
                // project. Descending into it attributes their conduct to this one.
                if (!REG_SKIP_DIRS.has(e.name) && !isForeignTree(abs))
                    stack.push(abs);
                continue;
            }
            const rel = path.relative(root, abs).replace(/\\/g, "/");
            const isCode = CODE_RE.test(rel);
            const isConfig = CONFIG_RE.test(rel);
            const isDoc = DOC_RE.test(rel);
            if (!isCode && !isConfig && !isDoc)
                continue;
            try {
                if (fs.statSync(abs).size > REG_MAX_BYTES)
                    continue;
                out.push({
                    rel,
                    text: fs.readFileSync(abs, "utf8"),
                    isCode,
                    isConfig,
                    isDoc,
                    isTestOrFixture: isTestOrFixture(rel),
                });
            }
            catch {
                // An unreadable file is not evidence of a problem.
            }
        }
    }
    return out;
}
/**
 * A `key: value` matcher that survives the ways config is actually written.
 *
 * Naive `\bkey\s*[:=]\s*value` fails on the single most common form there is —
 * `"human_review": false` — because the closing quote sits between the key and
 * the colon. Every one of these rules is aimed at JSON and YAML config, so that
 * one omission silently disabled a third of them. It cost ten test failures here;
 * in production it would have been ten silent misses, which is worse, because
 * nothing would have told us.
 */
export const keyValue = (key, value) => new RegExp(`["']?(?:${key})["']?\\s*[:=]\\s*["']?(?:${value})\\b`, "i");
/** `file:line [Art. X] detail` — the shape every regulatory finding renders as. */
export const renderFinding = (f) => `${f.file}:${f.line} [${f.article}] ${f.detail}`;
/**
 * Blank out regex literals and comments, leaving string literals intact.
 *
 * The asymmetry is deliberate and load-bearing.
 *
 * **Regex literals and comments are always definitions.** A rule that searches
 * for `human_review: false` necessarily contains the text `human_review` inside
 * its own pattern, and a doc comment explaining the rule contains it too. These
 * three checks reported themselves as violations the first time they ran against
 * this repository: the disclosure rule accused itself of suppressing disclosure,
 * and the record-keeping rule accused itself of deleting audit trails. The same
 * self-reference will occur in any customer codebase that does policy work.
 *
 * **String literals are not blanked**, because for these particular checks the
 * string *is* the evidence. `"human_review": false` in a JSON config is the
 * finding, and blanking quoted text would delete exactly what we came to look
 * for. That is the opposite of the choice made in the workmanship module, where
 * quoted text is noise — the right answer differs per rule, and getting it
 * backwards silently disables the check in one direction or the other.
 */
export function blankDefinitions(line) {
    return line
        // Comments first: a regex-looking fragment inside a comment is prose.
        .replace(/\/\/.*$/g, "")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\*.*$/g, "")
        // Regex literals: /.../ with flags, not preceded by a word character.
        .replace(/(^|[=(,:[\s])\/(?:\\.|\[[^\]]*\]|[^/\\\n])+\/[gimsuy]*/g, "$1//");
}
/**
 * Does any line in this file match, and where?
 *
 * Returns the 1-based line number, or 0. Callers use the position to report a
 * location a reader can open — a finding with no line number costs the reader
 * more than it saves them.
 *
 * Matching runs against the line with definitions blanked, so a rule never
 * reports the code that defines it.
 */
export function findLine(text, re) {
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
        if (re.test(blankDefinitions(lines[i])))
            return i + 1;
    }
    return 0;
}
/**
 * Does this file contain the pattern in code?
 *
 * Every presence test must route through here rather than probing raw text.
 * Testing `re.test(f.text)` directly bypasses definition-blanking, and the
 * bypass is invisible — the rule keeps working on customer code and quietly
 * misreports any file that defines or documents the pattern.
 */
export const matchesInCode = (text, re) => findLine(text, re) > 0;
/** Does any scanned file contain this pattern? Used for repo-wide presence tests. */
export function existsInTree(files, re, where = () => true) {
    for (const f of files) {
        if (f.isTestOrFixture || !where(f))
            continue;
        const line = findLine(f.text, re);
        if (line)
            return { found: true, file: f.rel, line };
    }
    return { found: false };
}
