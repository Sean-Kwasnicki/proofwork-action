import fs from "node:fs";
import path from "node:path";
import { isForeignTree } from "./testPaths.js";
/**
 * Is there a verification mechanism at all?
 *
 * ## The hole this closes
 *
 * Every other integrity check inspects tests that exist. `fake_green` looks for
 * skipped and hollowed-out tests; `workmanship` looks for tests that assert
 * nothing. Both are useless against the simplest evasion available to an agent:
 * **write no tests.**
 *
 * A repository with no test files made `fake_green` skip itself, because there
 * was nothing to scan. Skipping reads as "not applicable" and costs almost
 * nothing, so the cheapest way past the strictest part of this gate was to
 * produce no verification at all. An agent does not need to defeat a rule it can
 * decline to trigger.
 *
 * ## Why absence is a finding rather than a skip
 *
 * The distinction this project already draws for regulatory duties applies here:
 *
 *   skip  — the duty is not engaged (no source code to verify)
 *   fail  — the duty is engaged and unmet (real code, no verification)
 *
 * "We could not examine this" and "there was nothing to examine" are different
 * claims, and reporting the first as the second is how a gate manufactures a
 * clean result.
 *
 * ## Why it is not simply "no tests = fail"
 *
 * Plenty of repositories legitimately have no tests: documentation,
 * infrastructure manifests, a scratch prototype, a config bundle. Failing those
 * would be a false accusation, and a gate that cries wolf gets switched off —
 * which costs more than the evasion it prevents.
 *
 * So the rule is proportionate. The finding requires **substantial source code**
 * and **no verification whatsoever**, and the thresholds below are set where a
 * reasonable engineer would agree a test should exist.
 */
const FRAMEWORK_REFS = {
    iso42001: ["A.6.2.4 AI-System Verification and Validation"],
    nist: ["MEASURE 2.5", "MEASURE 2.3"],
    eu: ["Art. 15 Accuracy, Robustness and Cybersecurity"],
};
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork", ".cache",
]);
/**
 * Below this, a repository is a script or a prototype and a missing test suite
 * is a reasonable choice rather than an omission. Set deliberately low: the aim
 * is to exempt the genuinely trivial, not to grant a generous allowance.
 */
const MIN_SOURCE_FILES = 3;
/** Below this many lines of real code, the same reasoning applies. */
const MIN_SOURCE_LINES = 120;
/** A test file this small is a placeholder, not a suite. */
const MIN_TEST_LINES = 5;
const isTestFile = (p) => /\.(test|spec)\.[cm]?[jt]sx?$/i.test(p) ||
    /(^|\/)__tests__\//i.test(p) ||
    /(^|\/)(?:tests?|spec|e2e)\//i.test(p) ||
    /_test\.(py|go)$/i.test(p) ||
    /(^|\/)test_[^/]+\.py$/i.test(p);
const isSourceFile = (p) => /\.[cm]?[jt]sx?$|\.py$|\.rb$|\.go$|\.java$|\.cs$/i.test(p) &&
    !isTestFile(p) &&
    !/\.d\.ts$/i.test(p) &&
    !/\.config\.[cm]?[jt]s$/i.test(p);
/** Count real code lines: no blanks, no comment-only lines. */
function countCode(text) {
    return text
        .split(/\r?\n/)
        .filter((l) => {
        const t = l.trim();
        return t !== "" && !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*") && !t.startsWith("#");
    }).length;
}
/**
 * A `test` script that exits successfully without running anything.
 *
 * `"test": "echo \"Error: no test specified\" && exit 1"` is npm's default and is
 * honest — it fails. The dangerous shape is the one edited to exit 0, which
 * reports success to every CI system that calls it while running nothing at all.
 */
const PLACEHOLDER_TEST_SCRIPT = /^\s*(?:echo\b[^&|]*)?(?:&&\s*)?(?:exit\s+0|true)\s*$|no test specified.*exit\s+0/i;
const RUNNERS = ["vitest", "jest", "mocha", "ava", "tap", "jasmine", "karma", "pytest", "playwright", "cypress"];
export function surveyVerification(root, max = 900) {
    const survey = {
        sourceFiles: 0,
        sourceLines: 0,
        testFiles: 0,
        testLines: 0,
        declaredRunner: null,
        placeholderScript: null,
    };
    const stack = [root];
    let seen = 0;
    while (stack.length && seen < max) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            if (seen >= max)
                break;
            const abs = path.join(dir, e.name);
            if (e.isDirectory()) {
                // A nested repository belongs to another project; its code is not ours.
                if (!SKIP_DIRS.has(e.name) && !isForeignTree(abs))
                    stack.push(abs);
                continue;
            }
            const rel = path.relative(root, abs).replace(/\\/g, "/");
            const test = isTestFile(rel);
            const source = isSourceFile(rel);
            if (!test && !source)
                continue;
            let lines = 0;
            try {
                if (fs.statSync(abs).size > 400 * 1024)
                    continue;
                lines = countCode(fs.readFileSync(abs, "utf8"));
            }
            catch {
                continue;
            }
            seen += 1;
            if (test) {
                // A one-line stub is not a suite. Counting it would let an agent satisfy
                // this check with an empty file, which is the evasion one level up.
                if (lines >= MIN_TEST_LINES) {
                    survey.testFiles += 1;
                    survey.testLines += lines;
                }
            }
            else {
                survey.sourceFiles += 1;
                survey.sourceLines += lines;
            }
        }
    }
    // A declared runner is evidence tests were intended, which makes their absence
    // an omission rather than a decision.
    try {
        const pkgPath = path.join(root, "package.json");
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
            const deps = { ...pkg.devDependencies, ...pkg.dependencies };
            survey.declaredRunner = RUNNERS.find((r) => deps?.[r] !== undefined) ?? null;
            const script = pkg.scripts?.test;
            if (script && PLACEHOLDER_TEST_SCRIPT.test(script))
                survey.placeholderScript = script;
        }
    }
    catch {
        // A malformed package.json is not evidence about testing.
    }
    return survey;
}
export function runVerificationChecks(root) {
    const s = surveyVerification(root);
    const evidence = { survey: s, frameworks: FRAMEWORK_REFS };
    // Not enough code for the question to be meaningful. A script or a prototype
    // with no tests is a reasonable choice, and failing it would be an accusation
    // we cannot support.
    if (s.sourceFiles < MIN_SOURCE_FILES || s.sourceLines < MIN_SOURCE_LINES) {
        return [{
                id: "integrity.verification",
                title: "Verification mechanism",
                status: "skip",
                detail: `${s.sourceFiles} source file(s), ${s.sourceLines} line(s) of code — too small for a missing ` +
                    `test suite to be a finding`,
                evidence,
            }];
    }
    /**
     * A test script that exits 0 without running anything.
     *
     * Reported ahead of everything else because it is worse than having no tests.
     * No tests is a gap a reader can see; a green `npm test` that ran nothing is an
     * active false signal, and every CI system downstream reports success on it.
     */
    if (s.placeholderScript) {
        return [{
                id: "integrity.verification",
                title: "Verification mechanism",
                status: "fail",
                detail: `The "test" script exits successfully without running anything: \`${s.placeholderScript.slice(0, 80)}\`. ` +
                    `Every CI system that calls it reports a pass. This is worse than having no tests — an absent ` +
                    `suite is visible, a green run that tested nothing is not.`,
                evidence,
            }];
    }
    // Real code, no verification of any kind. The evasion this check exists for:
    // an agent cannot fake a test it never wrote, and skipping used to cost nothing.
    if (s.testFiles === 0) {
        return [{
                id: "integrity.verification",
                title: "Verification mechanism",
                status: "fail",
                detail: `${s.sourceFiles} source file(s) and ${s.sourceLines} line(s) of code with no test file ` +
                    `anywhere in the repository` +
                    (s.declaredRunner
                        ? `, although ${s.declaredRunner} is installed — tests were intended and never written.`
                        : `. Nothing in this project can detect a regression, so no claim about its behaviour can be checked.`),
                evidence,
            }];
    }
    /**
     * Tests exist but are vanishingly thin relative to the code.
     *
     * A warning rather than a failure: the ratio is a crude proxy, plenty of good
     * suites are compact, and failing on a number we cannot defend precisely would
     * be the kind of arbitrary judgement this gate avoids elsewhere.
     */
    const ratio = s.testLines / Math.max(1, s.sourceLines);
    if (ratio < 0.05) {
        return [{
                id: "integrity.verification",
                title: "Verification mechanism",
                status: "warn",
                detail: `${s.testFiles} test file(s), ${s.testLines} line(s) of test against ${s.sourceLines} line(s) ` +
                    `of code (${(ratio * 100).toFixed(1)}%). A suite this thin is unlikely to detect a regression ` +
                    `in most of what it sits beside.`,
                evidence,
            }];
    }
    return [{
            id: "integrity.verification",
            title: "Verification mechanism",
            status: "pass",
            detail: `${s.testFiles} test file(s), ${s.testLines} line(s) of test against ${s.sourceLines} line(s) of ` +
                `code — a verification mechanism exists and runs`,
            evidence,
        }];
}
