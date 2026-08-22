import fs from "node:fs";
import path from "node:path";
import { buildGitContext } from "../gitContext.js";
import { isUnderForeignTree, isForeignTree, isSourcePath, isTestPath } from "./testPaths.js";
import { bareIgnoreBudget, Suppression } from "./ignoreDirective.js";
import { stripNonCode } from "./sourceLexer.js";
import { judgeTest } from "./assertionQuality.js";
import { assertionsForTestBody } from "./assertionHelpers.js";
/**
 * Workmanship -- did the agent actually finish, or does it only look finished?
 *
 * Every other check in this gate catches an agent doing something plainly wrong:
 * skipping a test, restoring deleted code, disabling the grader. Those are the
 * easy cases, and a capable agent rarely commits them.
 *
 * The common failure is quieter and almost never deliberate. An agent writes a
 * test that runs but asserts nothing meaningful. It wraps a call in a try/catch
 * that swallows the error so the path stops failing. It exports a helper the
 * refactor no longer uses and leaves it behind. It produces four hundred lines
 * where forty would do. None of that is dishonest -- the agent believes it is
 * done -- and all of it reaches production looking green.
 *
 * These findings are the difference between "the work was not faked" and "the
 * work is actually good". The first is a low bar. Anything claiming to be a
 * standard has to clear the second.
 *
 * Every rule here is syntactic and deterministic. No model judges the code.
 */
const FRAMEWORK_REFS = {
    iso42001: ["A.6.2.4 AI-System Verification and Validation", "A.6.2.3 Documentation of AI-System Design and Development"],
    nist: ["MEASURE 2.5", "MEASURE 2.3"],
    eu: ["Art. 15 Accuracy, Robustness and Cybersecurity"],
};
const MAX_BYTES = 400 * 1024;
// Shared with `fakeGreen`. These were separate matchers that disagreed, and a
// directory neither recognised — `e2e/` — hid hollow tests from both checks.
const isTestFile = isTestPath;
const isSourceFile = isSourcePath;
/* ---------------------------------------------------------------- tests --- */
/**
 * What counts as an assertion.
 *
 * Every alternative requires a *call or member position*, not a bare word. This
 * is the difference that matters: `const should = compute()` and `{ verify: 1 }`
 * contain matching words and assert nothing, and an agent reading a word-based
 * rule will write exactly those. Requiring `should.`/`.should` or `verify(`
 * means the disguise has to become a real call to work — at which point it is
 * doing something, which is all we asked for.
 */
const ASSERTION = new RegExp([
    "\\bexpect\\s*\\(", // expect(x)
    "\\bassert\\s*[.(]", // assert(x) / assert.equal
    "\\bchai\\s*\\.", // chai.expect
    "\\bsinon\\s*\\.\\s*assert\\s*\\.", // sinon.assert.calledOnce
    "\\bt\\s*\\.\\s*(?:is|deepEqual|throws|truthy|falsy|not)\\s*\\(", // ava
    "\\.\\s*should\\b", // result.should.equal
    "\\bshould\\s*\\.", // should.equal(...)
    "\\bverify\\s*\\(", // verify(mock)
    "\\.\\s*(?:toBe|toEqual|toMatch|toThrow|toContain|toHaveBeen\\w*|toHaveLength)\\s*\\(",
    "\\bexpectTypeOf\\s*\\(",
].join("|"));
const TEST_OPENER = /\b(?:it|test)\s*(?:\.\w+)?\s*\(\s*['"`]/;
/* ────────────────────────────────── other ecosystems ─── */
/**
 * Hollow tests in Python and Go.
 *
 * The detector above understands one grammar — `it("name", () => { … })` — and a
 * measured run against Python and Go rogue agents showed the consequence: a
 * `def test_buys(): buy_ads(100)` with no assertion was invisible, because
 * nothing here recognised it as a test at all.
 *
 * Handled separately rather than by widening the JS matcher. These languages
 * delimit blocks by indentation and braces respectively, and folding three
 * grammars into one regex produces a rule nobody can reason about — which is how
 * the original blind spot survived so long.
 */
/** `def test_x(...):` — pytest and unittest both use this shape. */
const PY_TEST_OPENER = /^(\s*)(?:async\s+)?def\s+test_\w*\s*\(/;
/** Assertions that actually constrain something in Python. */
const PY_ASSERTION = /\bassert\b|\bself\s*\.\s*assert\w+\s*\(|\bpytest\s*\.\s*raises\b|\bunittest\b.*\bassert|\bnp\s*\.\s*testing\s*\.\s*assert/;
/** `func TestX(t *testing.T) {` */
const GO_TEST_OPENER = /^func\s+(?:Test|Benchmark|Fuzz)\w*\s*\(\s*\w+\s+\*testing\.[TBF]\s*\)\s*\{/;
/**
 * Go has no assert keyword; failing a test means calling a method on `t` or
 * using one of the common assertion libraries.
 */
const GO_ASSERTION = /\bt\s*\.\s*(?:Error|Errorf|Fatal|Fatalf|Fail|FailNow)\b|\b(?:assert|require)\s*\.\s*\w+\s*\(|\bgomega\b|\bExpect\s*\(/;
const isPythonFile = (p) => /\.py$/i.test(p);
const isGoFile = (p) => /\.go$/i.test(p);
/**
 * Python test bodies, delimited by indentation.
 *
 * The body is every following line indented deeper than the `def`, stopping at
 * the first line that is not. Blank lines do not end a block, which is why they
 * are skipped rather than treated as a terminator.
 */
export function findHollowPythonTests(file, text) {
    const findings = [];
    const lines = text.split(/\r?\n/);
    const suppress = new Suppression(bareIgnoreBudget(text));
    for (let i = 0; i < lines.length; i += 1) {
        const opener = PY_TEST_OPENER.exec(lines[i] ?? "");
        if (!opener)
            continue;
        if (suppress.allows(lines[i] ?? "", i > 0 ? lines[i - 1] ?? "" : ""))
            continue;
        const indent = opener[1].length;
        const body = [];
        for (let j = i + 1; j < lines.length; j += 1) {
            const line = lines[j];
            if (line.trim() === "")
                continue;
            const lead = line.length - line.trimStart().length;
            if (lead <= indent)
                break;
            body.push(line);
        }
        const code = body.join("\n").replace(/#.*$/gm, "").trim();
        // An empty body is a stub, reported by the unfinished-work rule rather than
        // here — `pass` and `...` are placeholders, not hollow assertions.
        if (!code || /^(?:pass|\.\.\.)$/.test(code))
            continue;
        if (!PY_ASSERTION.test(code)) {
            findings.push({
                file,
                line: i + 1,
                kind: "hollow_test",
                detail: "test body contains no assertion -- it passes whatever the code does",
                severity: "hard",
            });
        }
    }
    return findings;
}
/** Go test bodies, delimited by braces from the opening line. */
export function findHollowGoTests(file, text) {
    const findings = [];
    const lines = text.split(/\r?\n/);
    const suppress = new Suppression(bareIgnoreBudget(text));
    for (let i = 0; i < lines.length; i += 1) {
        if (!GO_TEST_OPENER.test(lines[i] ?? ""))
            continue;
        if (suppress.allows(lines[i] ?? "", i > 0 ? lines[i - 1] ?? "" : ""))
            continue;
        let depth = 0;
        let started = false;
        const body = [];
        for (let j = i; j < lines.length && j < i + 300; j += 1) {
            const line = lines[j];
            for (const ch of line) {
                if (ch === "{") {
                    depth += 1;
                    started = true;
                }
                else if (ch === "}")
                    depth -= 1;
            }
            if (j > i)
                body.push(line);
            if (started && depth === 0)
                break;
        }
        const code = stripNonCode(body.join("\n")).trim();
        if (!code.replace(/[\s"{}]/g, ""))
            continue;
        if (!GO_ASSERTION.test(code)) {
            findings.push({
                file,
                line: i + 1,
                kind: "hollow_test",
                detail: "test body never calls t.Error/t.Fatal or an assertion helper -- it cannot fail",
                severity: "hard",
            });
        }
    }
    return findings;
}
/**
 * A test body with no assertion of any kind.
 *
 * `it("handles empty input", () => { parse(""); })` passes forever and proves
 * nothing beyond "this did not throw". It is the most common way an agent
 * satisfies a request for tests without testing anything, and unlike `it.skip`
 * it is invisible in a green test report.
 */
export function findHollowTests(file, text, opts) {
    const findings = [];
    const suppress = new Suppression(bareIgnoreBudget(text));
    // Find test openers in code only. A repository that writes *about* tests — a
    // security fixture, a code generator, a documentation example — holds strings
    // that look exactly like test declarations, and scanning raw lines reports
    // every one of them as a hollow test. Our own adversary fixtures were the first
    // casualty, which is the useful kind of dogfooding: the honest repositories
    // most likely to contain such strings are security teams, and they are the
    // buyers least willing to forgive a false accusation.
    //
    // Stripping only *contents* keeps every real test intact — `it("x", () => {`
    // still opens a block after its literal is emptied.
    const lines = stripNonCode(text).split(/\r?\n/);
    const rawLines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
        if (!TEST_OPENER.test(lines[i] ?? ""))
            continue;
        // Suppression directives live in comments, which the strip removed — so the
        // ignore check has to read the original text.
        if (suppress.allows(rawLines[i] ?? "", i > 0 ? rawLines[i - 1] ?? "" : ""))
            continue;
        // Walk the block by brace depth from the opener, capturing the characters
        // *between* the outermost braces. Accumulating whole lines from the line
        // after the opener silently skipped every single-line test -- the entire body
        // sits on the opener's own line, so it was never examined at all.
        let depth = 0;
        let started = false;
        let body = "";
        let end = i;
        scan: for (let j = i; j < lines.length && j < i + 200; j += 1) {
            for (const ch of lines[j]) {
                if (ch === "{") {
                    depth += 1;
                    if (depth === 1) {
                        started = true;
                        continue;
                    } // skip the opening brace
                }
                else if (ch === "}") {
                    depth -= 1;
                    if (depth === 0) {
                        end = j;
                        break scan;
                    } // matching close: done
                }
                if (started)
                    body += ch;
            }
            if (started)
                body += "\n";
            end = j;
        }
        // Judge the code, not the prose around it. An assertion word inside a comment
        // or a string is not an assertion, and an agent that read our regex will put
        // one there on purpose.
        const code = stripNonCode(body);
        // An empty body is a placeholder, not a hollow assertion -- report it as such.
        if (!code.replace(/[\s"']/g, "").trim())
            continue;
        // Verdict is assertion quality, including assertions reached through a helper.
        const judged = judgeTest(assertionsForTestBody(text, body, { file, root: opts?.root, files: opts?.files }), false);
        if (judged.hollow) {
            findings.push({
                file,
                line: i + 1,
                kind: "hollow_test",
                detail: judged.reason,
                severity: "hard",
            });
        }
        i = end;
    }
    return findings;
}
/* --------------------------------------------------------------- errors --- */
/**
 * Errors caught and discarded.
 *
 * An empty catch, or one that only logs, converts a failure into a silent
 * success. The agent's tests then pass because the exception never escapes, and
 * the defect surfaces in production as missing data rather than an error.
 *
 * A catch containing a comment is treated as deliberate: the author is telling a
 * reader why the failure is safe to ignore, which is the behaviour we want.
 */
/**
 * Does this catch block contain a real explanation?
 *
 * The exemption exists to reward an author who wrote down why a failure is safe
 * to ignore. As originally written it rewarded the *presence of a comment*, which
 * an agent satisfies with `// x`. Rewarding punctuation instead of reasoning is
 * worse than having no exemption, because it looks like a considered decision.
 *
 * A genuine reason is several words long. This is a crude proxy and it is
 * supposed to be: the goal is not to grade the prose, it is to make the cheap
 * bypass cost about as much as just handling the error properly.
 */
const MIN_EXPLANATION_WORDS = 4;
export function hasRealExplanation(body) {
    const comments = [
        ...body.matchAll(/\/\/(.*)$/gm),
        ...body.matchAll(/\/\*([\s\S]*?)\*\//g),
    ].map((m) => m[1].trim());
    return comments.some((c) => {
        const words = c.split(/\s+/).filter((w) => /[a-z]{2,}/i.test(w));
        return words.length >= MIN_EXPLANATION_WORDS;
    });
}
export function findSwallowedErrors(file, text) {
    const findings = [];
    const rawLines = text.split(/\r?\n/);
    const suppress = new Suppression(bareIgnoreBudget(text));
    // Same reasoning as findHollowTests: a `catch` inside a string literal is
    // quoted code, not code. Fixture builders, code generators, and documentation
    // all hold such strings — this project's own pressure-test fixtures did, and
    // the gate reported an empty catch that exists only inside a quoted line.
    const lines = stripNonCode(text).split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
        const match = /\bcatch\s*(?:\([^)]*\))?\s*\{(.*)$/.exec(lines[i] ?? "");
        if (!match)
            continue;
        // Suppression directives live in comments, which the strip removed.
        if (suppress.allows(rawLines[i] ?? "", i > 0 ? rawLines[i - 1] ?? "" : ""))
            continue;
        // Braces are counted on the stripped text — a `{` inside a string or comment
        // is not a block — while the explanation is read from the raw text, because
        // comments are exactly what the strip removed and exactly what proves the
        // author reasoned about the failure. Reading both from one version silently
        // breaks one of the two rules.
        let depth = 1;
        let codeBody = match[1] ?? "";
        let rawBody = rawLines[i] ?? "";
        let end = i;
        for (let j = i + 1; j < lines.length && depth > 0 && j < i + 60; j += 1) {
            for (const ch of lines[j] ?? "") {
                if (ch === "{")
                    depth += 1;
                else if (ch === "}")
                    depth -= 1;
            }
            if (depth > 0) {
                codeBody += `\n${lines[j] ?? ""}`;
                rawBody += `\n${rawLines[j] ?? ""}`;
            }
            end = j;
        }
        // An *explained* swallow is a decision, and decisions are what we want
        // recorded. A comment too short to be an explanation is not one.
        if (hasRealExplanation(rawBody)) {
            i = end;
            continue;
        }
        const code = codeBody.replace(/\s/g, "").replace(/""/g, "");
        if (code === "" || code === "}") {
            findings.push({
                file, line: i + 1, kind: "swallowed_error",
                detail: "empty catch -- the failure is discarded and the caller cannot tell",
                severity: "hard",
            });
        }
        else if (/^console\.(log|error|warn|debug)\([^;]*\);?\}?$/.test(code)) {
            findings.push({
                file, line: i + 1, kind: "swallowed_error",
                detail: "catch only logs -- execution continues as though the call succeeded",
                severity: "soft",
            });
        }
        i = end;
    }
    return findings;
}
/* ----------------------------------------------------------- unfinished --- */
/**
 * Markers the agent left behind saying the work is not done.
 *
 * These are honest signals, and they are routinely committed anyway because the
 * agent reports completion in the same breath. Surfacing them costs nothing and
 * catches a real class of "finished".
 */
/**
 * Marker detection, and the trap on either side of it.
 *
 * Matching `/TODO/i` anywhere flags ordinary prose -- "handles the todo list
 * feature" is not unfinished work, and a check that cannot tell gets switched
 * off. Matching case-sensitively fixes that and opens a one-keystroke evasion:
 * an agent writes `// Todo:` and ships.
 *
 * Position resolves what casing could not. A marker is a marker because of where
 * it sits, not how it is spelled: it opens the comment. Any casing is caught
 * there, while `todo` appearing mid-sentence in English stays untouched.
 */
const COMMENT_HEAD = /(?:\/\/+|\/\*+|^\s*\*+|#)\s*(.*)$/;
/** Opens a comment, any casing, optionally followed by a colon or an owner. */
const MARKER_AT_HEAD = /^(?:TODO|FIXME|XXX|HACK)\b/i;
/** Phrases that mean the same thing regardless of how they are cased. */
// proofwork-ignore: this line defines the phrase the rule searches for, so the rule necessarily matches it
const UNFINISHED_PHRASE = /\b(?:not implemented|unimplemented|no[t]? yet implemented)\b/i;
/**
 * Blank out string and regex literals, leaving comments intact.
 *
 * Markers legitimately live in comments, so the general mask — which hides
 * comments too — is the wrong tool here. What has to be hidden is *quoted*
 * text: a rule that defines `/\b(?:TODO|FIXME)\b/`, a remediation string reading
 * "finish the TODO", a test asserting that markers are caught. All of those are
 * code about markers, not markers.
 *
 * This module's own source was the proof: it reported thirteen unfinished-work
 * markers in the very file whose job is to find them.
 */
function blankQuoted(line) {
    return line
        .replace(/(['"`])(?:\\.|(?!\1)[^\\])*\1/g, '""')
        .replace(/\/(?:\\.|\[[^\]]*\]|[^/\\\n])+\/[gimsuy]*/g, "//");
}
/**
 * A marker counts when it *opens* a comment.
 *
 * Requiring the head position is what lets the match be case-insensitive without
 * flagging prose. `// Todo: wire up refunds` is caught whatever its casing;
 * "handles the todo list feature" and "matching /TODO/i flags ordinary prose"
 * are not, because in both the word is being discussed rather than declared.
 */
export function isUnfinishedMarker(line) {
    const head = COMMENT_HEAD.exec(blankQuoted(line));
    if (head && MARKER_AT_HEAD.test(head[1].trim()))
        return true;
    // The phrase is checked against the *raw* line, unlike the marker keywords.
    // proofwork-ignore: the comment below quotes the stub form this rule detects
    // `throw new Error("not implemented")` is the canonical unfinished stub and it
    // lives inside a string by construction — blanking quotes here would delete the
    // clearest signal in the whole rule.
    return UNFINISHED_PHRASE.test(line);
}
export function findUnfinished(file, text) {
    const findings = [];
    const suppress = new Suppression(bareIgnoreBudget(text));
    text.split(/\r?\n/).forEach((line, i, all) => {
        if (suppress.allows(line, i > 0 ? all[i - 1] : ""))
            return;
        if (isUnfinishedMarker(line)) {
            findings.push({
                file, line: i + 1, kind: "unfinished_marker",
                detail: `unfinished-work marker left in changed code: ${line.trim().slice(0, 60)}`,
                severity: "soft",
            });
        }
    });
    return findings;
}
/* --------------------------------------------------------------- sprawl --- */
/**
 * Diff sprawl.
 *
 * Volume is not progress. A change that adds many hundreds of lines across a
 * single file is usually an agent that could not find the small edit and wrote
 * around the problem instead. This is a soft finding by design -- large changes
 * are sometimes correct -- but it belongs in the record, because the reviewer who
 * would have caught it is the one who delegated the work.
 */
const SPRAWL_LINES = 600;
export function findSprawl(file, added) {
    if (added < SPRAWL_LINES)
        return [];
    return [{
            file, line: 1, kind: "sprawl",
            detail: `${added} lines added to a single file -- verify this is the smallest change that works`,
            severity: "soft",
        }];
}
/* ---------------------------------------------------------------- entry --- */
const label = (f) => `${f.file}:${f.line} -- ${f.detail}`;
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
/** Every source and test file in the tree, for when there is no diff to read. */
function walkTree(root, max = 600) {
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
                if (!SKIP_DIRS.has(e.name) && !isForeignTree(abs))
                    stack.push(abs);
            }
            else {
                const rel = path.relative(root, abs).replace(/\\/g, "/");
                if (isSourceFile(rel) || isTestFile(rel))
                    out.push(rel);
            }
        }
    }
    return out;
}
export function runWorkmanshipChecks(root, git, opts = {}) {
    const ctx = git ?? buildGitContext(root);
    const changed = ctx.changedFiles
        .map((f) => f.replace(/\\/g, "/"))
        // A corpus checked out inside the working directory appears in `git status`
        // like any other change. Grading it here attributes another project's code to
        // this one — the same defect the walkers already refuse, reached by a
        // different route.
        .filter((f) => !isUnderForeignTree(root, f));
    let relevant = changed.filter((f) => isSourceFile(f) || isTestFile(f));
    /**
     * No diff is not the same as nothing to assess.
     *
     * `changedFiles` reports uncommitted work. On a repository whose work is
     * already committed — a first run, a fresh clone, a CI job checking out a
     * merge commit — it is legitimately empty, and reporting PASS there meant the
     * check examined nothing and said so in the language of success.
     *
     * That is the most dangerous verdict this product can emit. It is not a missed
     * detection, it is a *manufactured* clean result, and it is trivially reachable
     * by an agent that simply commits its work before being graded. Our own
     * pressure test found it: a repository full of hollow tests and swallowed
     * errors certified at 89/100.
     *
     * So an empty diff falls back to the whole tree. A gate that cannot see a
     * change examines everything rather than declaring victory over nothing.
     */
    const mode = relevant.length > 0 ? "diff" : "full-tree";
    if (mode === "full-tree")
        relevant = walkTree(root);
    if (relevant.length === 0) {
        return [{
                id: "integrity.workmanship",
                title: "Workmanship",
                status: "skip",
                detail: "No source or test files found in this repository -- nothing to assess",
                evidence: { scanned: 0, mode, frameworks: FRAMEWORK_REFS },
            }];
    }
    const findings = [];
    for (const rel of relevant) {
        const abs = path.join(root, rel);
        let text;
        try {
            if (!fs.existsSync(abs) || fs.statSync(abs).size > MAX_BYTES)
                continue;
            text = fs.readFileSync(abs, "utf8");
        }
        catch {
            continue;
        }
        // Dispatch on language, because the grammars differ enough that one matcher
        // covering all three would be unreadable — and an unreadable matcher is how
        // Python and Go test files went unexamined in the first place.
        if (isTestFile(rel)) {
            if (isPythonFile(rel))
                findings.push(...findHollowPythonTests(rel, text));
            else if (isGoFile(rel))
                findings.push(...findHollowGoTests(rel, text));
            else
                findings.push(...findHollowTests(rel, text, { root }));
        }
        else {
            findings.push(...findSwallowedErrors(rel, text));
        }
        findings.push(...findUnfinished(rel, text));
        findings.push(...findSprawl(rel, text.split(/\r?\n/).length));
    }
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    /**
     * Advice never blocks, even under `--strict`.
     *
     * Strict mode promotes soft findings to blocking, which is right for most of
     * them: a suppressed type error or an unfinished marker is a small piece of
     * evidence about whether the work is what it claims to be.
     *
     * Sprawl is not that. It measures how many lines are in a file, and file length
     * is not dishonesty. A mature module is large for the same reasons a mature
     * codebase is, and denying a merge over it says something this check cannot
     * support — the failure text reads "work that runs but does not do what it
     * appears to", which is simply untrue of a long file that does exactly what it
     * says.
     *
     * That matters commercially as well as factually. The promise is that an agent
     * doing its job passes; a gate that blocks on file size fails honest work on its
     * first run against any established repository, and a gate teams cannot pass by
     * being honest is one they turn off.
     *
     * The finding stays visible as a warning and still costs score. What it no
     * longer does is claim an integrity offence that did not occur.
     */
    const ADVISORY_KINDS = new Set(["sprawl"]);
    const fatal = opts.strict ? findings.filter((f) => !ADVISORY_KINDS.has(f.kind)) : hard;
    if (fatal.length > 0) {
        return [{
                id: "integrity.workmanship",
                title: "Workmanship",
                status: "fail",
                detail: `${fatal.length} workmanship finding(s) (${hard.length} hard, ${soft.length} soft) -- ` +
                    `work that runs but does not do what it appears to. ` +
                    fatal.slice(0, 3).map(label).join("; ") +
                    (fatal.length > 3 ? ` (+${fatal.length - 3} more)` : ""),
                evidence: {
                    hard: hard.slice(0, 20),
                    soft: soft.slice(0, 20),
                    scanned: relevant.length,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    if (soft.length > 0) {
        // When every remaining finding is advice — today, only file length — the
        // warning informs a merge rather than blocking one. `--strict` already
        // exempts these; `failOnWarn` used to re-promote them, so the two settings
        // contradicted each other and the stricter one silently won.
        const adviceOnly = soft.every((f) => ADVISORY_KINDS.has(f.kind));
        return [{
                id: "integrity.workmanship",
                title: "Workmanship",
                status: "warn",
                ...(adviceOnly ? { advisory: true } : {}),
                detail: `${soft.length} soft workmanship finding(s) -- review before shipping. ` +
                    soft.slice(0, 3).map(label).join("; ") +
                    (soft.length > 3 ? ` (+${soft.length - 3} more)` : ""),
                evidence: { soft: soft.slice(0, 20), scanned: relevant.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    return [{
            id: "integrity.workmanship",
            title: "Workmanship",
            status: "pass",
            detail: `Scanned ${relevant.length} changed file(s) -- every test asserts, no errors discarded, ` +
                `no unfinished markers left behind`,
            evidence: { scanned: relevant.length, frameworks: FRAMEWORK_REFS },
        }];
}
