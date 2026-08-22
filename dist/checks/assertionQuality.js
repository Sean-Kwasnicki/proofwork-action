/**
 * Constraining vs tautological assertions.
 *
 * Regex "has expect(" is a candidate finder only. The verdict is this module.
 * Do not import `typescript` — the packed Action cannot ship it.
 *
 * On incorporate: copy to `src/checks/assertionQuality.ts` and point
 * `findHollowTests` at `testIsHollow`.
 */
import { SPAN_CODE, nonCodeMask } from "./sourceLexer.js";
import { bodyLooksEmpty, extractTests } from "./extractTests.js";
const TAUTOLOGY_MATCHERS = new Set([
    "tobetruthy",
    "tobefalsy",
    "tobedefined",
    "tobeundefined",
    "tobenull",
    "tobenan",
    "ok",
    "tobeok",
]);
const MOCK_WEAK = new Set([
    "tohavebeencalled",
    "tohavebeencalledtimes",
    "tohavebeencalledonce",
]);
const MOCK_STRONG = new Set([
    "tohavebeencalledwith",
    "tohavebeenlastcalledwith",
    "tohavebeennthcalledwith",
]);
const CONSTRAINING_MATCHERS = new Set([
    "tobe",
    "toequal",
    "tostrictequal",
    "tomatch",
    "tomatchobject",
    "tothrow",
    "tothrowerror",
    "tocontain",
    "tocontainequal",
    "tohavelength",
    "tohaveproperty",
    "tobecloseto",
    "tobegreaterthan",
    "tobegreaterthanorequal",
    "tobelessthan",
    "tobelessthanorequal",
    "tobeinstanceof",
    "tomatchsnapshot",
    "tomatchinline snapshot",
    "rejects",
    "resolves",
]);
const IDENT = /[A-Za-z_$][A-Za-z0-9_$]*/;
function isCodeWord(src, mask, i, word) {
    if (mask[i] !== SPAN_CODE)
        return false;
    if (src.slice(i, i + word.length) !== word)
        return false;
    const before = i === 0 ? "" : src[i - 1];
    const after = src[i + word.length] ?? "";
    if (/[A-Za-z0-9_$]/.test(before))
        return false;
    if (/[A-Za-z0-9_$]/.test(after))
        return false;
    return true;
}
function skipWs(src, i) {
    while (i < src.length && /\s/.test(src[i]))
        i += 1;
    return i;
}
/** Parse a parenthesized group. Depth only moves on SPAN_CODE parens. */
function parseParen(src, open, mask) {
    if (src[open] !== "(")
        return null;
    let depth = 0;
    let inner = "";
    let innerStart = open + 1;
    for (let i = open; i < src.length; i += 1) {
        const c = src[i];
        if (mask[i] === SPAN_CODE && c === "(") {
            depth += 1;
            if (depth === 1) {
                innerStart = i + 1;
                continue;
            }
        }
        else if (mask[i] === SPAN_CODE && c === ")") {
            depth -= 1;
            if (depth === 0) {
                const lead = inner.length - inner.trimStart().length;
                return { inner: inner.trim(), innerStart: innerStart + lead, end: i + 1 };
            }
        }
        if (depth >= 1)
            inner += c;
    }
    return null;
}
function splitTopLevel(src, innerStart, mask, sep) {
    const parts = [];
    let buf = "";
    let depth = 0;
    for (let i = 0; i < src.length; i += 1) {
        const c = src[i];
        const m = mask[innerStart + i] ?? SPAN_CODE;
        if (m === SPAN_CODE && (c === "(" || c === "[" || c === "{"))
            depth += 1;
        else if (m === SPAN_CODE && (c === ")" || c === "]" || c === "}"))
            depth -= 1;
        if (m === SPAN_CODE && c === sep && depth === 0) {
            parts.push(buf.trim());
            buf = "";
            continue;
        }
        buf += c;
    }
    if (buf.trim())
        parts.push(buf.trim());
    return parts;
}
function normalizeExpr(expr) {
    return expr.replace(/\s+/g, "").trim();
}
function isBooleanLiteral(expr) {
    return /^(?:true|false)$/.test(expr.trim());
}
function isTrivialLiteral(expr) {
    const t = expr.trim();
    return /^(?:true|false|null|undefined|\d+(?:\.\d+)?)$/.test(t) || /^['"`]/.test(t);
}
function lastMatcher(chain) {
    const last = chain[chain.length - 1] ?? "";
    return last.toLowerCase();
}
function classifyExpect(actual, matcher, expected) {
    const m = matcher.toLowerCase();
    if (m === "expecttypeof" || m.startsWith("expecttypeof"))
        return "type-only";
    if (TAUTOLOGY_MATCHERS.has(m))
        return "tautology-matcher";
    if (MOCK_WEAK.has(m))
        return "mock-only";
    if (MOCK_STRONG.has(m))
        return "constraining";
    const a = normalizeExpr(actual);
    const e = normalizeExpr(expected);
    // expect(true) / expect(true).toBe(true) — ARG is the boolean, not a field.
    if (!matcher && isBooleanLiteral(actual))
        return "literal-true";
    if (isBooleanLiteral(actual) && (m === "tobe" || m === "toequal" || m === "tostrictequal")) {
        return "literal-true";
    }
    if (a && e && a === e)
        return "same-node";
    if (CONSTRAINING_MATCHERS.has(m))
        return "constraining";
    if (m === "tobe" || m === "toequal")
        return "constraining";
    return "unknown";
}
function readMemberChain(src, start, mask) {
    const names = [];
    let i = start;
    while (i < src.length) {
        i = skipWs(src, i);
        if (!IDENT.test(src[i] ?? ""))
            break;
        const m = IDENT.exec(src.slice(i));
        if (!m || mask[i] !== SPAN_CODE)
            break;
        names.push(m[0]);
        i += m[0].length;
        i = skipWs(src, i);
        if (src[i] === ".") {
            i += 1;
            continue;
        }
        break;
    }
    return { names, end: i };
}
export function findAssertions(body) {
    const mask = nonCodeMask(body);
    const found = [];
    let i = 0;
    while (i < body.length) {
        if (mask[i] !== SPAN_CODE) {
            i += 1;
            continue;
        }
        if (isCodeWord(body, mask, i, "expect") || isCodeWord(body, mask, i, "expectTypeOf")) {
            const callee = isCodeWord(body, mask, i, "expectTypeOf") ? "expectTypeOf" : "expect";
            i += callee.length;
            i = skipWs(body, i);
            // `expect.soft(x)` is `expect` with a modifier, not a missing assertion.
            // Leaving `.soft` unparsed was how tautologies minted: the detector saw
            // no `expect(` and either passed a hollow body or, once hollow was wired,
            // failed honest tests that only used soft expects.
            let soft = false;
            if (callee === "expect" && body[i] === ".") {
                const k = skipWs(body, i + 1);
                if (isCodeWord(body, mask, k, "soft")) {
                    soft = true;
                    i = skipWs(body, k + 4);
                }
            }
            if (body[i] !== "(")
                continue;
            const arg = parseParen(body, i, mask);
            if (!arg) {
                i += 1;
                continue;
            }
            let j = skipWs(body, arg.end);
            const chain = [];
            let expected = "";
            while (body[j] === ".") {
                j += 1;
                j = skipWs(body, j);
                const ident = IDENT.exec(body.slice(j));
                if (!ident || mask[j] !== SPAN_CODE)
                    break;
                const name = ident[0];
                j += name.length;
                j = skipWs(body, j);
                if (body[j] === "(") {
                    const call = parseParen(body, j, mask);
                    if (!call)
                        break;
                    chain.push(name);
                    expected = call.inner;
                    j = call.end;
                    j = skipWs(body, j);
                }
                else {
                    chain.push(name);
                }
            }
            const matcher = lastMatcher(chain);
            const klass = callee === "expectTypeOf"
                ? "type-only"
                : classifyExpect(arg.inner, matcher, expected);
            found.push({
                callee: soft ? "expect.soft" : callee,
                matcher: chain.join(".") || "(bare)",
                actual: arg.inner,
                expected,
                klass,
                soft,
            });
            i = j;
            continue;
        }
        if (isCodeWord(body, mask, i, "assert")) {
            const chain = readMemberChain(body, i, mask);
            i = chain.end;
            i = skipWs(body, i);
            if (body[i] !== "(")
                continue;
            const arg = parseParen(body, i, mask);
            if (!arg) {
                i += 1;
                continue;
            }
            const method = (chain.names[1] ?? "ok").toLowerCase();
            const parts = splitTopLevel(arg.inner, arg.innerStart, mask, ",");
            const actual = parts[0] ?? arg.inner;
            const expected = parts[1] ?? "";
            let klass = "unknown";
            if (method === "ok" || method === "isok")
                klass = "tautology-matcher";
            else if (method === "equal" ||
                method === "strictequal" ||
                method === "deepequal" ||
                method === "throws" ||
                method === "rejects" ||
                method === "match") {
                klass =
                    normalizeExpr(actual) && normalizeExpr(actual) === normalizeExpr(expected)
                        ? "same-node"
                        : "constraining";
            }
            found.push({
                callee: chain.names.join("."),
                matcher: method,
                actual,
                expected,
                klass,
            });
            i = arg.end;
            continue;
        }
        i += 1;
    }
    return found;
}
export function judgeTest(assertions, empty) {
    if (empty)
        return { hollow: false, reason: "empty — unfinished, not hollow", constraining: 0 };
    const constraining = assertions.filter((a) => a.klass === "constraining").length;
    if (constraining >= 1)
        return { hollow: false, reason: "has constraining assertion", constraining };
    if (assertions.length === 0) {
        return { hollow: true, reason: "test body contains no assertion — it passes whatever the code does", constraining: 0 };
    }
    const kinds = new Set(assertions.map((a) => a.klass));
    if (kinds.has("literal-true") || kinds.has("same-node")) {
        return { hollow: true, reason: "assertion does not constrain a result (literal or same-node)", constraining: 0 };
    }
    if (kinds.has("tautology-matcher")) {
        return { hollow: true, reason: "sole assertions are tautological matchers (toBeDefined / toBeTruthy / …)", constraining: 0 };
    }
    if (kinds.has("mock-only")) {
        return { hollow: true, reason: "sole assertions are mock-called checks with no arguments", constraining: 0 };
    }
    if (kinds.has("type-only")) {
        return { hollow: true, reason: "sole assertions are type-level (expectTypeOf) and cannot fail at runtime", constraining: 0 };
    }
    return { hollow: true, reason: "assertions present but none constrain a value", constraining: 0 };
}
export function analyseTestFile(text) {
    return extractTests(text).map((t) => {
        const empty = bodyLooksEmpty(t.body);
        const assertions = empty ? [] : findAssertions(t.body);
        const judged = judgeTest(assertions, empty);
        return {
            line: t.line,
            nameHint: t.nameHint,
            empty,
            assertions,
            constraining: judged.constraining,
            hollow: judged.hollow,
            reason: judged.reason,
        };
    });
}
/** Drop-in replacement for the ASSERTION-regex branch of `findHollowTests`. */
export function findHollowTests(file, text) {
    return analyseTestFile(text)
        .filter((t) => t.hollow)
        .map((t) => ({
        file,
        line: t.line,
        kind: "hollow_test",
        detail: t.reason,
        severity: "hard",
    }));
}
export function fileHasConstrainingAssertion(text) {
    return analyseTestFile(text).some((t) => t.constraining > 0);
}
/** Exposed for tests — not a production heuristic. */
export const __test = { isTrivialLiteral, classifyExpect, normalizeExpr };
