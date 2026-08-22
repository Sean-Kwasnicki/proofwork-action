import fs from "node:fs";
import path from "node:path";
import { buildGitContext } from "../gitContext.js";
import { lineOffsets, nonCodeMask, SPAN_CODE, SPAN_STRING } from "./sourceLexer.js";
import { isUnderForeignTree, isForeignTree, isTestPath } from "./testPaths.js";
const WALK_SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
/** Every test file in the tree, for when there is no diff to read. */
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
                // A nested repository belongs to another project; its code is not ours.
                if (!WALK_SKIP_DIRS.has(e.name) && !isForeignTree(abs))
                    stack.push(abs);
            }
            else {
                const rel = path.relative(root, abs).replace(/\\/g, "/");
                if (isTestPath(rel))
                    out.push(rel);
            }
        }
    }
    return out;
}
export const SUSPICIOUS_PATTERNS = [
    { id: "describe.skip", re: /\bdescribe\.skip\s*\(/, why: "skipped describe suite", severity: "hard" },
    { id: "it.skip", re: /\bit\.skip\s*\(/, why: "skipped test", severity: "hard" },
    { id: "test.skip", re: /\btest\.skip\s*\(/, why: "skipped test", severity: "hard" },
    // `skipIf(true)` is a skip that never runs and does not match `it.skip(`.
    // An agent that has read the matcher table writes this and the suite stays green.
    {
        id: "skipIf_const",
        re: /\b(?:it|test|describe)\.skipIf\s*\(\s*(?:true|!0|!false|1\s*===\s*1)\s*\)/,
        why: "skipIf with a constant-true predicate — the test never runs",
        severity: "hard",
    },
    // Bracket notation is identical at runtime and defeated the dot-anchored rules
    // above: it["skip"](…) and it[`skip`](…) skip a test exactly as it.skip does.
    {
        id: "bracket_skip",
        re: /\b(?:it|test|describe)\s*\[\s*["'`](?:skip|only)["'`]\s*\]\s*\(/,
        why: "skipped or focused test via bracket notation",
        severity: "hard",
    },
    // Computed access hides the modifier behind a variable. Flagged on suspicion:
    // there is no legitimate reason to reach a test modifier through a variable.
    {
        id: "computed_modifier",
        re: /\b(?:it|test|describe)\s*\[\s*[A-Za-z_$][\w$]*\s*\]\s*\(/,
        why: "test modifier resolved through a variable — hides skip/only from review",
        severity: "hard",
    },
    { id: "describe.only", re: /\bdescribe\.only\s*\(/, why: "focused suite (.only) — hides the rest of the suite", severity: "hard" },
    { id: "it.only", re: /\bit\.only\s*\(/, why: "focused test (.only) — common agent shortcut", severity: "hard" },
    { id: "test.only", re: /\btest\.only\s*\(/, why: "focused test (.only) — common agent shortcut", severity: "hard" },
    { id: "fit", re: /\bfit\s*\(/, why: "focused test (fit)", severity: "hard" },
    { id: "fdescribe", re: /\bfdescribe\s*\(/, why: "focused suite (fdescribe)", severity: "hard" },
    { id: "xit", re: /\bxit\s*\(/, why: "disabled test (xit)", severity: "hard" },
    { id: "xdescribe", re: /\bxdescribe\s*\(/, why: "disabled suite (xdescribe)", severity: "hard" },
    { id: "xtest", re: /\bxtest\s*\(/, why: "disabled test (xtest)", severity: "hard" },
    { id: "skip_true", re: /\b(?:it|test)\s*\([^)]+,\s*\{\s*skip:\s*true/, why: "skip: true option", severity: "hard" },
    { id: "pending", re: /\bpending\s*\(/, why: "pending() placeholder", severity: "hard" },
    {
        id: "always_true_expect",
        re: /expect\s*\(\s*true\s*\)\s*\.\s*toBe(?:Truthy)?\s*\(\s*true\s*\)/,
        why: "tautology assertion",
        severity: "hard",
    },
    {
        id: "always_false_expect",
        re: /expect\s*\(\s*false\s*\)\s*\.\s*toBe(?:Falsy)?\s*\(\s*false\s*\)/,
        why: "tautology assertion (false/false)",
        severity: "hard",
    },
    {
        id: "expect_true_truthy",
        re: /expect\s*\(\s*true\s*\)\s*\.\s*toBeTruthy\s*\(\s*\)/,
        why: "tautology toBeTruthy(true)",
        severity: "hard",
    },
    {
        id: "expect_same_literal",
        re: /expect\s*\(\s*(\d+|['"`][^'"`]+['"`])\s*\)\s*\.\s*toBe\s*\(\s*\1\s*\)/,
        why: "literal compared to itself (no behavior under test)",
        severity: "hard",
    },
    {
        id: "expect_defined_only",
        // Match sole/closing weak assert (end of line or before closing brace)
        re: /expect\s*\(\s*[^)]+\s*\)\s*\.\s*toBeDefined\s*\(\s*\)\s*;?\s*(?:\}|$)/,
        why: "weak toBeDefined-only assertion (common fake coverage)",
        severity: "hard",
    },
    {
        id: "expect_ok_only",
        re: /expect\s*\(\s*[^)]+\s*\)\s*\.\s*toBeOk\s*\(\s*\)/,
        why: "weak toBeOk-only assertion",
        severity: "hard",
    },
    {
        id: "expect_truthy_only",
        re: /expect\s*\(\s*[^)]+\s*\)\s*\.\s*toBeTruthy\s*\(\s*\)\s*;?\s*(?:\}|$)/,
        why: "weak toBeTruthy-only assertion without behavior check",
        severity: "hard",
    },
    {
        id: "expect_null_only",
        re: /expect\s*\(\s*[^)]+\s*\)\s*\.\s*not\s*\.\s*toBeNull\s*\(\s*\)\s*;?\s*(?:\}|$)/,
        why: "weak not.toBeNull-only assertion",
        severity: "hard",
    },
    {
        id: "mock_return_hardcoded_success",
        re: /\.(?:mockReturnValue|mockResolvedValue)\s*\(\s*\{\s*ok\s*:\s*true/,
        why: "hardcoded success mock — often untested path",
        severity: "hard",
    },
    {
        id: "vi_mocked_from_sut_path",
        re: /vi\.mock\s*\(\s*['"`]\.?\.?\/[^'"`]+['"`]/,
        why: "module mock of relative path — high risk of mocking the unit under test",
        severity: "hard",
    },
    {
        id: "jest_mocked_from_sut_path",
        re: /jest\.mock\s*\(\s*['"`]\.?\.?\/[^'"`]+['"`]/,
        why: "module mock of relative path — high risk of mocking the unit under test",
        severity: "hard",
    },
    {
        id: "force_pass_comment",
        re: /\/\/\s*(?:force\s*pass|make\s*(?:it\s*)?pass|skip\s*assertion)/i,
        why: "comment admitting the test is being forced green",
        severity: "hard",
        scope: "prose",
    },
    {
        id: "empty_test",
        re: /\b(?:it|test)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:async\s*)?\(\s*\)\s*=>\s*\{\s*\}\s*\)/,
        why: "empty test body",
        severity: "hard",
    },
    {
        id: "todo_test",
        re: /\b(?:it|test|describe)\.todo\s*\(/,
        why: "todo test marker",
        severity: "hard",
    },
    {
        id: "mock_controllers_claim",
        re: /mock\s+controllers|all tests are passing|tests?\s+pass(ing)?\s+now/i,
        why: "progress language that often accompanies fake green",
        severity: "hard",
        scope: "prose",
    },
    {
        id: "vi_mock_entire_module_comment",
        re: /\/\/\s*mock\s+everything|\/\*\s*skip\s+real\s+impl/i,
        why: "comment suggesting tests avoid real implementation",
        severity: "hard",
        scope: "prose",
    },
    {
        id: "any_cast_escape",
        re: /\bas\s+any\b|\bas\s+unknown\s+as\b/,
        why: "type escape hatch in a test — often hides broken contracts",
        severity: "soft",
    },
    {
        id: "ts_ignore_in_test",
        re: /@ts-ignore|@ts-expect-error/,
        why: "suppressed type error inside test file",
        severity: "soft",
        scope: "prose",
    },
];
export function scanTextForFakeGreen(file, text) {
    const findings = [];
    const lines = text.split(/\r?\n/);
    // A pattern that *begins* inside a string literal is quoting code, not being
    // code: a security fixture, a documentation example, a code generator. Scanning
    // raw lines reported ten such "skipped tests" in this project's own adversarial
    // fixtures — and the repositories most likely to contain strings like these
    // belong to the security teams evaluating us.
    //
    // The test is deliberately about where the match *starts*, not whether the line
    // contains a string. Several rules here are findings precisely because of what a
    // string says — `vi.mock('./relative')` is one — and blanking string contents
    // would delete the signal along with the noise.
    const mask = nonCodeMask(text);
    const offsets = lineOffsets(text);
    lines.forEach((line, idx) => {
        const prev = idx > 0 ? lines[idx - 1] ?? "" : "";
        if (/proofwork-ignore-next-line/i.test(prev) || /proofwork-ignore/i.test(line)) {
            return;
        }
        const lineStart = offsets[idx] ?? 0;
        for (const pat of SUSPICIOUS_PATTERNS) {
            // Fresh regex per probe: several rules carry /g, and a shared lastIndex
            // makes detection depend on scan order — the kind of nondeterminism that
            // shows up as a flaky gate and destroys trust in the verdict.
            //
            // Every occurrence on the line is examined, not just the first. Stopping at
            // the first match meant a masked-out occurrence hid every later one, so
            // `const x = "// force pass"; // force pass` reported nothing: the string
            // was correctly skipped and the real admission after it was never reached.
            // A one-line decoy is a cheap evasion, and this rule set is public.
            const re = new RegExp(pat.re.source, `${pat.re.flags.replace("g", "")}g`);
            for (let m = re.exec(line); m !== null; m = re.exec(line)) {
                // Where the match *starts* decides whether it counts.
                //
                //   code-scoped  — must begin in code. A rule about what the program does
                //                  has nothing to say about a comment or a quoted example.
                //   prose-scoped — must begin in code or a comment, never inside a string
                //                  literal. These rules exist to catch the admission in
                //                  `// force pass so CI goes green`, so they cannot skip
                //                  comments; but `const src = "// force pass"` is a
                //                  fixture, and quoting an offence is not committing one.
                //
                // Both halves have drawn blood. Masking prose rules disabled four of them
                // outright; not masking them made this gate fail on its own repository,
                // reading the detector's test fixtures as the thing they detect.
                const span = mask[lineStart + m.index];
                if (pat.scope === "prose" ? span === SPAN_STRING : span !== SPAN_CODE) {
                    // A zero-width match would spin here forever.
                    if (m.index === re.lastIndex)
                        re.lastIndex += 1;
                    continue;
                }
                findings.push({ file, id: pat.id, why: pat.why, line: idx + 1, severity: pat.severity });
                // One finding per rule per line. The line is already named in the report,
                // and repeating it would let a single line dominate the count.
                break;
            }
        }
    });
    return findings;
}
/**
 * Render findings as `file:line — reason`, newest problem first.
 *
 * The findings already carry file and line; until now only the counts reached the
 * `detail` string, so the CLI, the GitHub check, and any agent reading the proof
 * were told *that* something was wrong but never *where*. An agent cannot repair
 * what it cannot locate, and a human shouldn't have to open the JSON evidence to
 * find a line number. Capped at three so the summary line stays readable — the
 * full set is still in `evidence`.
 */
export function describeFindings(findings, max = 3) {
    const shown = findings
        .slice(0, max)
        .map((f) => `${f.file}:${f.line} — ${f.why}`)
        .join("; ");
    const rest = findings.length - Math.min(findings.length, max);
    return rest > 0 ? `${shown} (+${rest} more)` : shown;
}
// Path classification lives in one shared module. This check and `workmanship`
// previously carried separate matchers that disagreed, and hollow tests placed in
// a directory neither recognised were invisible to both.
export function runFakeGreenChecks(root, git, opts = {}) {
    const strict = Boolean(opts.strict);
    const ctx = git ?? buildGitContext(root);
    // Foreign trees are excluded here too. The walker refuses to descend into a
    // corpus, but `changedFiles` reaches it directly.
    let files = ctx.changedFiles.filter((f) => isTestPath(f) && !isUnderForeignTree(root, f));
    /**
     * An empty diff is not a clean repository.
     *
     * `changedFiles` reports uncommitted work, so it is legitimately empty on a
     * first run, a fresh clone, or a CI checkout of a merge commit. Returning PASS
     * there reported success for a scan that never happened — and an agent reaches
     * that state simply by committing before it is graded.
     *
     * Our own pressure test caught it: a repository containing a skipped test and
     * two hollow ones certified at 89/100 because nothing was uncommitted.
     */
    const mode = files.length > 0 ? "diff" : "full-tree";
    if (mode === "full-tree")
        files = walkTestFiles(root);
    if (files.length === 0) {
        return [
            {
                id: "integrity.fake_green",
                title: "Anti-fake-green heuristics",
                status: "skip",
                detail: "No test files found in this repository — nothing to scan",
                evidence: { mode },
            },
        ];
    }
    const findings = [];
    for (const rel of files) {
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
        findings.push(...scanTextForFakeGreen(rel, text));
    }
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    // Max-capacity bar: under --strict / strictIntegrity, soft findings are FAIL.
    const fatal = strict ? [...hard, ...soft] : hard;
    if (fatal.length > 0) {
        return [
            {
                id: "integrity.fake_green",
                title: "Anti-fake-green heuristics",
                status: "fail",
                detail: `${strict
                    ? `Strict integrity FAIL — ${fatal.length} finding(s) (${hard.length} hard, ${soft.length} soft)`
                    : `Suspicious test patterns in changed tests (${hard.length} hard, ${soft.length} soft)`} → ${describeFindings(fatal)}`,
                evidence: { hard: hard.slice(0, 20), soft: soft.slice(0, 10), strict },
            },
        ];
    }
    if (soft.length > 0) {
        return [
            {
                id: "integrity.fake_green",
                title: "Anti-fake-green heuristics",
                status: "warn",
                detail: `Soft fake-green language found (${soft.length}) — review manually → ${describeFindings(soft)}`,
                evidence: { soft: soft.slice(0, 20) },
            },
        ];
    }
    return [
        {
            id: "integrity.fake_green",
            title: "Anti-fake-green heuristics",
            status: "pass",
            detail: `Scanned ${files.length} changed test file(s) — no suspicious patterns`,
            evidence: { files },
        },
    ];
}
