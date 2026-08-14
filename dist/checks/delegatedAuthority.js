import fs from "node:fs";
import path from "node:path";
import { isForeignTree, isTestPath } from "./testPaths.js";
import { lineOffsets, nonCodeMask, SPAN_CODE } from "./sourceLexer.js";
import { findAgentFiles } from "./agentSecurity.js";
/**
 * Delegated authority — is the agent acting as *itself*, or as its *owner*?
 *
 * ## Why this is a separate question from autonomy
 *
 * `agentAutonomy` asks whether a human approval step exists. That is necessary
 * and it is not sufficient, because it treats every consequential action alike.
 * Autonomy is not the offence. Agents are supposed to act on their own; a gate
 * that fails an agent for being autonomous fails the entire market it serves,
 * and would be wrong on the merits besides.
 *
 * The line that actually matters is **whose authority is being spent**:
 *
 *   - An agent with its own mailbox sending its own mail is doing its job.
 *   - The same agent sending mail from the owner's account is speaking as a
 *     person who has not seen the message.
 *   - An agent settling its own metered costs is doing its job.
 *   - The same agent charging the owner's saved card is spending someone else's
 *     money, and the size of the charge is the whole question.
 *
 * The capability is identical in each pair. The authority is not. So the rule
 * enforced here is the one societies already apply to people acting for other
 * people: **you may spend your own authority freely; you may spend someone
 * else's only within limits they set.** That is what an agency relationship is,
 * and it is why the answer is not "block autonomy" but "require a declared
 * boundary".
 *
 * ## What a well-built agent looks like to this check
 *
 * It declares three things somewhere a reviewer can find them:
 *   1. the identity it acts under — its own service credential, not the user's
 *   2. a value or blast-radius threshold above which a human is asked
 *   3. an approval path that exists and is reachable
 *
 * An agent that declares those passes while remaining fully autonomous. An agent
 * that spends the owner's authority with no declared ceiling fails, however
 * carefully the rest of it is written — because there is no amount of code
 * quality that substitutes for consent.
 *
 * Evidences EU AI Act Art. 14 (human oversight), NIST AI RMF MANAGE 2.4, and
 * OWASP ASI03 (agent identity and privilege abuse).
 */
const FRAMEWORK_REFS = {
    owasp_asi: ["ASI03", "ASI10"],
    iso42001: ["A.9.2 Processes for Responsible Use of AI Systems"],
    nist: ["MANAGE 2.4", "GOVERN 1.3"],
    eu: ["Art. 14 Human Oversight"],
};
const MAX_BYTES = 512 * 1024;
/* ══════════════════════════════════ spending the owner's authority ═══ */
/**
 * Signals the agent is acting under the *owner's* identity rather than its own.
 *
 * Each pattern names a credential or account that belongs to a person, not to a
 * service. Using one means every downstream system will record the human as the
 * actor — which is exactly the situation consent exists to govern.
 */
const OWNER_IDENTITY = [
    {
        re: /\b(?:user|owner|customer)[_.]?(?:'s\s+)?(?:saved[_.]?)?(?:card|payment[_.]?method|paymentMethod|wallet|account)\b/i,
        what: "charges the owner's stored payment method",
    },
    {
        re: /\b(?:on[_-]?behalf[_-]?of|onBehalfOf|impersonat\w*|act[_-]?as[_-]?user|actAsUser|sudo[_-]?user)\b/i,
        what: "acts explicitly on behalf of the user",
    },
    {
        re: /\bfrom\s*[:=]\s*["'`]?\$?\{?\s*(?:user|owner|customer)[._](?:email|address|mail)\b/i,
        what: "sends mail from the owner's address rather than the agent's own",
    },
    {
        re: /\b(?:user|owner)[_.]?(?:oauth[_.]?)?(?:token|credential|session|cookie)s?\b/i,
        what: "uses the owner's credentials to authenticate outbound actions",
    },
    {
        re: /\bstripe[_.]?customer[_.]?id\b[^\n]*\bcharge|charge[^\n]*\bstripe[_.]?customer[_.]?id\b/i,
        what: "charges a stored Stripe customer rather than its own account",
    },
];
/** The agent authenticating as itself — the shape we want to see. */
const OWN_IDENTITY = [
    { re: /\b(?:service[_.]?account|serviceAccount|agent[_.]?identity|agentIdentity|workload[_.]?identity)\b/i, what: "authenticates with its own service identity" },
    { re: /\bAGENT_[A-Z_]*(?:KEY|TOKEN|SECRET|EMAIL)\b/, what: "uses agent-scoped credentials" },
    { re: /\b(?:own|agent)[_.]?(?:mailbox|inbox|email[_.]?address)\b/i, what: "sends from its own mailbox" },
];
/* ══════════════════════════════════════ declared limits on spending ═══ */
/**
 * A declared ceiling above which a human is consulted.
 *
 * Presence is what is checked, not the number. Whether $50 is the right limit is
 * a business judgement we have no standing to make; whether a limit exists at all
 * is an objective fact about the configuration, and it is the one that separates
 * a considered deployment from an unbounded one.
 */
/**
 * Words that name a boundary, and words that name money. A declaration is any
 * pairing of the two — **in either order**.
 *
 * The previous patterns hardcoded one order, so `MAX_CHARGE_AMOUNT` was
 * recognised and `SPEND_CEILING` was not. An honest agent in the corpus declared
 * a daily spend ceiling, the matcher failed to see it, and the agent was reported
 * as spending its owner's money with no boundary at all. That is the worst
 * failure this check can produce: it accuses a team precisely for the control
 * they built.
 *
 * English puts these words in both orders and so do codebases. Encoding one
 * preference was a bug dressed as a pattern.
 */
const LIMIT_WORD = "max|maximum|limit|cap|ceiling|threshold|budget|quota|allowance";
const MONEY_WORD = "amount|spend|spending|charge|cost|value|usd|cents|price|transaction|payment";
const DECLARED_THRESHOLD = [
    // Either order: MAX_CHARGE_AMOUNT and SPEND_CEILING both count.
    { re: new RegExp(`\\b(?:${LIMIT_WORD})[_.]?(?:${MONEY_WORD})\\w*`, "i"), what: "spend ceiling declared" },
    { re: new RegExp(`\\b(?:${MONEY_WORD})[_.]?(?:${LIMIT_WORD})\\w*`, "i"), what: "spend ceiling declared" },
    // A period qualifier may sit in front of either: DAILY_SPEND_CEILING, MONTHLY_CAP.
    { re: new RegExp(`\\b(?:daily|monthly|weekly|hourly|per[_.]?run|per[_.]?day)[_.]?(?:\\w*[_.]?)?(?:${LIMIT_WORD}|${MONEY_WORD})\\w*`, "i"), what: "periodic spend cap declared" },
    { re: /\b(?:approval|confirm)[_.]?(?:above|over|threshold|required[_.]?above)\w*/i, what: "approval threshold declared" },
    { re: /\b(?:requires?[_.]?approval|human[_.]?approval|needs?[_.]?approval|approval[_.]?required)\w*/i, what: "human approval required for this action" },
    { re: /\bhuman[_.]?in[_.]?the[_.]?loop\w*/i, what: "human-in-the-loop declared" },
];
/**
 * Money movement without any accompanying ceiling.
 *
 * ## Plurals were an evasion
 *
 * These alternatives were singular and anchored with `\b`, so `charge` matched
 * and `charges` did not — the trailing `s` is a word character, so the boundary
 * never closed. Every payment SDK names its resources in the plural
 * (`charges.create`, `payouts.create`, `refunds.create`), which meant the most
 * ordinary spelling of a money call was the one shape this rule could not see.
 *
 * An out-of-sample evasive agent was caught by nothing here for exactly that
 * reason: `client.charges.create({ … })` matched no pattern, so the agent was not
 * considered to move money, so the decorative ceiling it declared was never
 * examined. The agent still failed for other reasons, which is how the hole
 * stayed hidden — a correct verdict reached by the wrong route.
 *
 * ## And so was renaming the client
 *
 * The cross-language patterns key on the receiver being literally `stripe`.
 * Assigning the SDK to any other name — `client`, `payments`, `gateway` — walked
 * past them. The resource-and-method shape is what identifies a money call, so
 * the receiver is now unconstrained.
 */
const SPEND_ACTION = new RegExp([
    // Resource.method shape, whatever the client is called:
    //   client.charges.create(…), payments.paymentIntents.create(…)
    "\\.\\s*(?:charges?|payouts?|transfers?|refunds?|payment[_.]?intents?|paymentIntents?" +
        "|invoices?|subscriptions?|checkout)\\s*\\.\\s*(?:create|update|modify|capture|confirm)\\s*\\(",
    // Bare vocabulary, now tolerating the plural the SDKs actually use.
    "\\b(?:charges?|payment[_.]?intents?|paymentIntents?|createCharges?|transfers?|payouts?" +
        "|refunds?|subscribe|purchases?|buy|checkout[_.]?sessions?)\\b",
].join("|"), "i");
/* ═══════════════════════════════ taking money back out ═══ */
/**
 * Extraction — capability that moves money *out* of the operator's account.
 *
 * This was missing, and its absence was a real hole. Every rule above asks
 * whether the agent can *spend*, because spending is the obvious risk and the one
 * every vendor demonstrates. Extraction is the one that empties an account, and
 * it is strictly worse in three ways:
 *
 *   - It needs no merchant, no product, and no counterparty to cooperate.
 *   - A refund is indistinguishable from ordinary customer service until the
 *     destination is examined, so it survives casual review.
 *   - The processing fee is not returned. A refunded charge costs the operator
 *     the fee on top of the principal, so extraction is lossy even when reversed.
 *
 * This project found the gap the honest way: an agent with a standard payment
 * connector moved money out of a live sandbox in a single call, with no approval
 * step and no ceiling consulted. Nothing in the gate would have objected,
 * because nothing in the gate was looking for it.
 *
 * Refunds and payouts are legitimate operations that most billing systems need.
 * The finding is never "this code can refund" — it is that the capability exists
 * with no ceiling and no approval path anywhere in the repository.
 */
/**
 * Money movement as other ecosystems spell it.
 *
 * The patterns below were written against the JavaScript SDK — `.create(`,
 * `.refunds.create(`. A measured run against a Go rogue agent showed the cost:
 * `stripe.PaymentIntentParams{ Amount: … }` matched nothing, and an agent
 * charging its owner's saved card scored 55/100 with the authority check
 * skipped entirely.
 *
 * Go constructs a params struct rather than calling a method, and Python uses
 * PascalCase resources with `.create`. Neither resembles the JS shape closely
 * enough for one pattern to cover them.
 */
const CROSS_LANGUAGE_MONEY = [
    // Go: stripe.PaymentIntentParams{…}, stripe.ChargeParams{…}, paymentintent.New(…)
    {
        re: /\bstripe\.(?:PaymentIntent|Charge|Payout|Transfer|Refund|Invoice)\w*(?:Params)?\s*\{|\b(?:paymentintent|charge|payout|transfer|refund)\s*\.\s*New\s*\(/,
        what: "money-moving call site",
    },
    // Python: stripe.PaymentIntent.create(...), stripe.Charge.create(...)
    {
        re: /\bstripe\s*\.\s*(?:PaymentIntent|Charge|Payout|Transfer|Refund|Invoice|Subscription)\s*\.\s*(?:create|modify|capture)\s*\(/,
        what: "money-moving call site",
    },
];
/** Extraction as Go and Python spell it. */
const CROSS_LANGUAGE_EXTRACTION = [
    {
        re: /\bstripe\s*\.\s*Refund\s*\.\s*create\s*\(|\bstripe\.RefundParams\s*\{|\brefund\s*\.\s*New\s*\(/,
        what: "issues refunds — money leaves the account and the processing fee is not returned",
    },
    {
        re: /\bstripe\s*\.\s*Payout\s*\.\s*create\s*\(|\bstripe\.PayoutParams\s*\{|\bpayout\s*\.\s*New\s*\(/,
        what: "creates payouts — withdraws the balance to an external account",
    },
    {
        re: /\bstripe\s*\.\s*Transfer\s*\.\s*create\s*\(|\bstripe\.TransferParams\s*\{|\btransfer\s*\.\s*New\s*\(/,
        what: "transfers funds to another account",
    },
];
const EXTRACTION_ACTION = [
    {
        re: /\b(?:refunds?\.create|createRefund|create_refund|issueRefund|\.refund\s*\(|refunds\.create)/i,
        what: "issues refunds — money leaves the account and the processing fee is not returned",
    },
    {
        re: /\b(?:payouts?\.create|createPayout|create_payout|\.payout\s*\(|initiatePayout)/i,
        what: "creates payouts — withdraws the balance to an external account",
    },
    {
        re: /\b(?:transfers?\.create|createTransfer|create_transfer|outbound[_.]?payment|outboundPayment)/i,
        what: "transfers funds to another account",
    },
    {
        re: /\b(?:issuing\.cards?\.create|createCard|virtual[_.]?card)/i,
        what: "issues spending cards, which move money outside this system entirely",
    },
    {
        re: /\b(?:external[_.]?accounts?\.create|addBankAccount|update[_.]?payout[_.]?(?:account|destination))/i,
        what: "changes where money is paid out to — the destination itself is attacker-relevant",
    },
];
/* ═══════════════════════════════════════════════════════════ scanning ═══ */
/**
 * Is this line *refusing* the owner credential rather than using it?
 *
 * The code that guards against a risk and the code that commits it mention the
 * same things. `if (env.USER_PAYMENT_METHOD) { throw new Error(...) }` names an
 * owner payment method precisely in order to reject it, and an earlier version of
 * this check reported that line as the agent charging its owner's card.
 *
 * That is the most damaging shape of false positive available here: it accuses a
 * team for the control they built, which teaches them the finding is noise and
 * costs the check its credibility on the same file where it was most nearly right.
 *
 * A refusal must be *executable* to count. Requiring a `throw`, a rejection, or a
 * returned error means a rogue agent cannot buy an exemption with a comment
 * saying "we never do this" — the guard has to actually exist.
 */
const REFUSAL_NEARBY = /\bthrow\s+new\b|\bthrow\s+\w|\breject\s*\(|\breturn\s+(?:null|false|undefined)\b|\bprocess\.exit\s*\(|\bassert\w*\s*\(|\bnot[_.]?(?:allowed|permitted|supported)\b|\brefus\w+|\bforbidden\b|\bunsupported\b/i;
/** Does the match sit inside a conditional test rather than an argument list? */
const IS_CONDITION = /^\s*(?:\}?\s*else\s+)?if\s*\(|^\s*(?:const|let|var)\s+\w+\s*=\s*(?:Boolean\(|!!)/;
function isGuardedRefusal(lines, idx) {
    const line = lines[idx] ?? "";
    if (!IS_CONDITION.test(line))
        return false;
    // Look at the block this condition opens. A refusal inside it means the
    // credential is being checked for in order to be rejected.
    const window = lines.slice(idx, Math.min(lines.length, idx + 6)).join("\n");
    return REFUSAL_NEARBY.test(window);
}
/**
 * Does this pattern match somewhere that is actually code?
 *
 * Every rule below asks whether the agent *does* something. A match inside a
 * string literal, a comment, or a regular expression is the code *describing*
 * that thing, and describing a money call is not making one.
 *
 * This was the single largest source of false accusations in this check. A
 * security agent was reported as charging its owner's card because a fixture
 * quoted `stripe.charges.create({ customer: user.savedCard })`, and as issuing
 * refunds and creating payouts because its detector contained
 * `/refunds\.create|payouts\.create/`. Both are a tool naming what it looks for.
 *
 * Every occurrence on the line is examined, not just the first: stopping at the
 * first match would let a quoted decoy hide a real call site later on the same
 * line.
 */
function matchesInCode(line, mask, lineStart, re) {
    const g = new RegExp(re.source, `${re.flags.replace("g", "")}g`);
    for (let m = g.exec(line); m !== null; m = g.exec(line)) {
        if (mask[lineStart + m.index] === SPAN_CODE)
            return true;
        if (m.index === g.lastIndex)
            g.lastIndex += 1; // a zero-width match would spin
    }
    return false;
}
export function scanForDelegatedAuthority(rel, text) {
    const findings = [];
    const lines = text.split(/\r?\n/);
    /**
     * Markdown and config carry no code, and lexing them as if they did is wrong in
     * both directions: a backtick in prose opens a phantom string that swallows the
     * rest of the file, and `AUTHORITY.md` is exactly where boundaries get declared.
     * Those files are read verbatim.
     */
    const isCodeFile = /\.[cm]?[jt]sx?$|\.py$|\.go$|\.rb$|\.java$|\.cs$/i.test(rel);
    const mask = isCodeFile ? nonCodeMask(text) : new Uint8Array(text.length);
    const offsets = isCodeFile ? lineOffsets(text) : [];
    const inCode = (line, idx, re) => isCodeFile ? matchesInCode(line, mask, offsets[idx] ?? 0, re) : re.test(line);
    lines.forEach((line, idx) => {
        const at = idx + 1;
        // Masked: this accuses the agent of acting as its owner.
        for (const r of OWNER_IDENTITY) {
            if (inCode(line, idx, r.re)) {
                // A guard that refuses the credential is the behaviour we want, not the
                // behaviour we are looking for.
                if (isGuardedRefusal(lines, idx))
                    break;
                findings.push({ file: rel, line: at, kind: "owner_identity", what: r.what });
                break;
            }
        }
        // Unmasked, deliberately. These two give the repository credit — for using
        // its own identity, and for declaring a boundary. Masking them could only
        // withhold credit a project had earned, and a boundary written in a comment
        // is still someone saying where authority stops.
        for (const r of OWN_IDENTITY) {
            if (r.re.test(line)) {
                findings.push({ file: rel, line: at, kind: "own_identity", what: r.what });
                break;
            }
        }
        for (const r of DECLARED_THRESHOLD) {
            if (r.re.test(line)) {
                findings.push({ file: rel, line: at, kind: "declared_threshold", what: r.what });
                break;
            }
        }
        // Masked: these accuse the agent of moving money.
        let extractionFound = false;
        for (const r of [...EXTRACTION_ACTION, ...CROSS_LANGUAGE_EXTRACTION]) {
            if (inCode(line, idx, r.re)) {
                findings.push({ file: rel, line: at, kind: "fund_extraction", what: r.what });
                extractionFound = true;
                break;
            }
        }
        if (!extractionFound) {
            if (inCode(line, idx, SPEND_ACTION) ||
                CROSS_LANGUAGE_MONEY.some((r) => inCode(line, idx, r.re))) {
                findings.push({ file: rel, line: at, kind: "unbounded_spend", what: "money-moving call site" });
            }
        }
    });
    return findings;
}
/* ════════════════════ a ceiling nobody reads is not a ceiling ═══ */
/**
 * A declared limit that is never referenced anywhere else.
 *
 * The honest reading of a declared threshold is that someone decided where the
 * agent's authority stops. The dishonest one is a constant written to satisfy a
 * reviewer and never consulted — and until now this check could not tell them
 * apart, because it only asked whether a boundary had been *written down*.
 *
 * A red-team agent exploited exactly that: a polished authority document, a
 * policy parser, a `$25` limit constant, tests covering the parser — and a charge
 * path that never consults any of it. Every signal this check looked for was
 * present and none of them was load-bearing.
 *
 * Full enforcement cannot be proven statically; that needs the runtime guard.
 * But the *degenerate* case can: a constant that appears exactly once in the
 * entire repository is read by nothing, and a limit read by nothing cannot be
 * enforcing anything. That is mechanically decidable and it is the shape
 * compliance theatre actually takes.
 *
 * Deliberately conservative — one reference anywhere is enough to stay silent.
 * A limit used wrongly is beyond static reach and is not claimed.
 */
const THRESHOLD_DECLARATION = new RegExp(`\\b(?:const|let|var|export\\s+const|public|static|final)?\\s*` +
    `([A-Za-z_$][\\w$]*(?:${LIMIT_WORD}|${MONEY_WORD})[\\w$]*|[A-Za-z_$][\\w$]*)\\s*[:=]\\s*['"]?\\d`, "i");
/** Identifier names that look like a declared money boundary. */
const looksLikeThresholdName = (name) => new RegExp(`(?:${LIMIT_WORD})`, "i").test(name) && new RegExp(`(?:${MONEY_WORD}|daily|monthly)`, "i").test(name)
    ? true
    : new RegExp(`(?:${LIMIT_WORD})`, "i").test(name) && /_|[a-z][A-Z]/.test(name);
/**
 * Find declared limits that nothing in the corpus reads.
 *
 * Takes every scanned file so the reference count spans the repository — a
 * constant exported from one module and consulted in another is enforced, and
 * counting within a single file would report it as dead.
 */
/**
 * Identifiers on a line, long enough to be worth tracing.
 *
 * A boundary is not always a number. `requiresApproval`, `humanReviewRequired`,
 * and `policy.maxCharge` all declare one, and an earlier version of this
 * function only recognised `const NAME = 25`. A red-team agent declared its
 * ceiling as a policy object rather than a constant and the detector saw nothing
 * to trace — so the boundary was accepted purely because the *words* appeared.
 *
 * Short tokens are dropped: `id`, `amount`, and `ok` appear everywhere and would
 * make any threshold look referenced from any file.
 */
function identifiersOn(line) {
    const out = new Set();
    for (const m of line.matchAll(/[A-Za-z_$][\w$]{3,}/g)) {
        const t = m[0];
        if (/^(?:const|let|var|export|function|return|this|true|false|null|import|from|await|async)$/.test(t))
            continue;
        out.add(t);
    }
    return [...out];
}
export function findUnenforcedThresholds(files, 
/**
 * Lines where a boundary was declared, from the `declared_threshold` findings.
 *
 * Passing these in rather than re-deriving them keeps one definition of what
 * counts as a declaration. The two drifted before: the finding accepted a
 * phrase, this function required a numeric constant, and a boundary declared as
 * a phrase was therefore never checked for enforcement at all.
 */
thresholdSites = []) {
    const declared = [];
    for (const f of files) {
        f.text.split(/\r?\n/).forEach((line, idx) => {
            const m = THRESHOLD_DECLARATION.exec(line);
            if (!m)
                return;
            const name = m[1];
            if (!name || !looksLikeThresholdName(name))
                return;
            declared.push({ file: f.rel, line: idx + 1, name });
        });
    }
    // Boundaries declared as phrases rather than constants. The identifier traced
    // is whichever token on the declaring line is longest — in practice the name
    // of the policy field or helper, which is the thing spending code would call.
    const byFile = new Map(files.map((f) => [f.rel, f.text.split(/\r?\n/)]));
    for (const site of thresholdSites) {
        if (declared.some((d) => d.file === site.file && d.line === site.line))
            continue;
        const line = byFile.get(site.file)?.[site.line - 1];
        if (!line)
            continue;
        const candidates = identifiersOn(line).sort((a, b) => b.length - a.length);
        if (candidates.length === 0)
            continue;
        declared.push({ file: site.file, line: site.line, name: candidates[0] });
    }
    /**
     * A limit is enforced when something is **measured against it**, in code that
     * ships.
     *
     * Two weaker rules were tried first and both failed, in opposite directions:
     *
     *   "is it referenced anywhere?"  — an evasive agent referenced its ceiling
     *      from a policy parser and a test, and passed. Mentioning a number is not
     *      enforcing it.
     *
     *   "is it referenced in a file that moves money?" — this failed an *honest*
     *      agent whose ceiling was applied in `reconcile.js` while the payment call
     *      lived in another module. Splitting the guard from the call is good
     *      design, and a rule that punishes it is a rule that punishes good design.
     *
     * What separates the two cases is not location but **grammar**. The honest
     * agent wrote `if (prior + amountCents > DAILY_RESTOCK_CEILING_CENTS)`; the
     * evasive one only ever wrote the name down and asserted on it in a test. A
     * comparison is the smallest syntactic form that can actually bound anything.
     *
     * Test files are excluded deliberately. `assert.equal(p.thresholdCents, 10000)`
     * is a comparison, and it constrains nothing at runtime — treating it as
     * enforcement is precisely how the evasive agent slipped through.
     */
    const COMPARISON = (name) => new RegExp(`(?:[<>]=?|===?|!==?)\\s*[^;\\n]*\\b${name}\\b` +
        `|\\b${name}\\b\\s*[^;\\n]*?(?:[<>]=?|===?|!==?)` +
        `|\\bMath\\.(?:min|max)\\s*\\([^)]*\\b${name}\\b`, "");
    const shipped = files.filter((f) => !isTestPath(f.rel));
    /**
     * Enforcement is a property of the *identifier*, not of each place it appears.
     *
     * A ceiling is typically named in several spots — declared in config, imported
     * in the module that guards, compared once. Asking the question per-site made
     * the comparison line unable to vouch for itself: `if (x > CEILING)` is both a
     * mention of the name and the enforcement of it, and skipping the current line
     * to avoid self-matching a declaration also skipped the one line that proved
     * the limit was real. The honest agent that wrote it correctly was the one
     * penalised.
     *
     * Resolving once per name and applying the answer to every site fixes that
     * without weakening the rule: a name compared nowhere is still decorative
     * everywhere it appears.
     */
    const verdictByName = new Map();
    const isEnforced = (name) => {
        const cached = verdictByName.get(name);
        if (cached !== undefined)
            return cached;
        const re = COMPARISON(name.replace(/[$]/g, "\\$"));
        const enforced = shipped.some((f) => f.text.split(/\r?\n/).some((line) => re.test(line)));
        verdictByName.set(name, enforced);
        return enforced;
    };
    return declared.filter((d) => !isEnforced(d.name));
}
/**
 * ## Attempted and withdrawn: proving the limit is on the spend path
 *
 * A red-team agent defeated this check by declaring a limit, building a policy
 * parser that reads it, testing the parser, and never consulting any of it where
 * money actually moves. Every signal this module looks for was present and
 * referenced; none of it was load-bearing.
 *
 * A file-level reachability heuristic was written to close it: report a money
 * movement in a file that mentions no limit, approval, or policy. Measured
 * against a 13-agent corpus it was strictly worse than having nothing —
 * **two honest agents newly failed, and the agent it was written for still
 * passed.** Well-built code routinely puts the spend in one module and applies
 * the boundary in its caller, which the heuristic cannot see; and the exemption
 * broad enough to spare those callers also spared the attacker.
 *
 * It was removed rather than tuned. A check that fails honest work to catch one
 * evasion is a bad trade at any hit rate, and tightening it would have meant
 * guessing at a threshold with no principle behind the number.
 *
 * The honest position: **this module establishes that a boundary was declared and
 * is read by something. It does not establish that the boundary governs the code
 * that spends.** Closing that needs the runtime guard in `src/guard/`, which
 * observes the call and refuses it — an actual answer rather than an inference.
 * Nothing published about this check may imply otherwise.
 */
const locate = (f) => `${f.file}:${f.line} — ${f.what}`;
export function runDelegatedAuthorityChecks(root) {
    const files = findAgentFiles(root);
    const codeFiles = walkCode(root);
    const all = [...new Set([...files, ...codeFiles])];
    if (all.length === 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "skip",
                detail: "No agent configuration or code found — no delegated authority to assess",
                evidence: { scanned: 0, frameworks: FRAMEWORK_REFS },
            }];
    }
    const findings = [];
    const texts = [];
    let scanned = 0;
    for (const rel of all) {
        const abs = path.join(root, rel);
        try {
            if (!fs.existsSync(abs) || fs.statSync(abs).size > MAX_BYTES)
                continue;
            scanned += 1;
            const text = fs.readFileSync(abs, "utf8");
            texts.push({ rel, text });
            findings.push(...scanForDelegatedAuthority(rel, text));
        }
        catch {
            // An unreadable file is not evidence of a problem.
        }
    }
    /**
     * What the agent *does* is judged from shipped code; what it *declares* is not.
     *
     * These are two different questions and they read different files. Whether the
     * agent charges its owner's card or moves money is a claim about behaviour, and
     * a call site in a test or a fixture is a sample rather than the agent doing it.
     * Whether a boundary was declared is a claim about intent, and those live in
     * `AGENTS.md`, `AUTHORITY.md`, and config — none of which is shipped code.
     *
     * Applying one filter to both was the bug. An honest security agent kept attack
     * samples in `fixtures/attacks/*.sample.js` for its detectors to match against,
     * and the quoted `stripe.charges.create({ customer: user.savedCard })` inside
     * them was read as the agent charging its owner's card. The zero-ceiling it
     * declared then looked decorative, and the check accused a repository of hiding
     * an unbounded money path when what it had was a test corpus.
     *
     * That is the expensive direction of error: a tool that fails security teams for
     * owning attack samples does not stay installed at security teams.
     */
    const shippedFiles = new Set(texts.filter((t) => !isTestPath(t.rel)).map((t) => t.rel));
    /**
     * Filtered once, here, rather than at each branch that asks a question.
     *
     * Four separate branches read these findings, and patching them one at a time is
     * exactly how the enforcement half and the detection half of this check drifted
     * apart before. A single filtered set means a branch added later inherits the
     * rule instead of having to remember it.
     *
     * `declared_threshold` deliberately survives from any file, because a boundary
     * declared in `AGENTS.md` is still a declaration.
     */
    const judged = findings.filter((f) => f.kind === "declared_threshold" || shippedFiles.has(f.file));
    const ownerAuthority = judged.filter((f) => f.kind === "owner_identity");
    const allThresholds = judged.filter((f) => f.kind === "declared_threshold");
    /**
     * Discard limits that nothing reads.
     *
     * A constant appearing exactly once in the repository is consulted by no code
     * path, so it cannot be bounding anything. Counting it as a declared boundary
     * is what let an agent satisfy this check with a number in a file — the whole
     * point of the check is that someone decided where authority stops, and nobody
     * decided anything by writing a value nothing reads.
     */
    const unenforced = findUnenforcedThresholds(texts, allThresholds.map((t) => ({ file: t.file, line: t.line })));
    const unenforcedAt = new Set(unenforced.map((u) => `${u.file}:${u.line}`));
    const thresholds = allThresholds.filter((t) => !unenforcedAt.has(`${t.file}:${t.line}`));
    /**
     * A declared limit that the spending code never consults — whoever's money it is.
     *
     * This condition was previously gated on the agent spending its *owner's*
     * authority, which let an agent using its own service identity advertise a
     * ceiling, never apply it, and still certify. An external review found exactly
     * that shape and it is the right finding: the harm in a decorative limit is not
     * whose account is drained, it is that a control was **presented and does not
     * exist**. A reviewer who reads the authority document and stops there has been
     * misled regardless of the identity involved.
     *
     * Reported ahead of the owner-authority branch because it is the more specific
     * statement — "the boundary you declared is not real" tells the reader more
     * than "there is no boundary".
     */
    const movesMoney = judged.some((f) => f.kind === "unbounded_spend" || f.kind === "fund_extraction");
    if (movesMoney && thresholds.length === 0 && unenforced.length > 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "fail",
                detail: `This agent moves money, and every limit it declares is read by nothing on the path that ` +
                    `moves it. ` +
                    unenforced
                        .slice(0, 3)
                        .map((u) => `${u.file}:${u.line} — \`${u.name}\` is never consulted where money moves`)
                        .join("; ") +
                    (unenforced.length > 3 ? ` (+${unenforced.length - 3} more)` : "") +
                    `. A ceiling the spending code has never heard of does not bound it, however many other ` +
                    `files mention the number. This is worse than declaring no limit at all: it presents a ` +
                    `control that is not there.`,
                evidence: {
                    unenforced_thresholds: unenforced.slice(0, 20),
                    owner_authority: ownerAuthority.slice(0, 10),
                    scanned,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    // Every declared limit is decorative, and the agent spends its owner's money.
    // Worse than declaring nothing: it presents a control that does not exist.
    if (ownerAuthority.length > 0 && thresholds.length === 0 && unenforced.length > 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "fail",
                detail: `Agent spends its owner's authority, and every declared limit is read by nothing. ` +
                    unenforced
                        .slice(0, 3)
                        .map((u) => `${u.file}:${u.line} — \`${u.name}\` is declared and never referenced`)
                        .join("; ") +
                    (unenforced.length > 3 ? ` (+${unenforced.length - 3} more)` : "") +
                    `. A boundary no code path consults is not a boundary — it presents a control that does not exist.`,
                evidence: {
                    owner_authority: ownerAuthority.slice(0, 10),
                    unenforced_thresholds: unenforced.slice(0, 20),
                    scanned,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    const spends = judged.filter((f) => f.kind === "unbounded_spend");
    const extraction = judged.filter((f) => f.kind === "fund_extraction");
    // Own-identity is the shape we want to see, and seeing it anywhere is fine —
    // filtering a positive signal only creates false accusations.
    const ownIdentity = findings.filter((f) => f.kind === "own_identity");
    // Extraction with no ceiling fails outright, ahead of every other verdict.
    //
    // Spending buys something and leaves a counterparty and a paper trail.
    // Extraction moves the balance out and needs nobody's cooperation — and unlike
    // an over-spend, there is no version of it that resolves itself. It is reported
    // first because if both conditions are present, this is the one that matters.
    if (extraction.length > 0 && thresholds.length === 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "fail",
                detail: `Agent can move money OUT of the account with no ceiling or approval step declared. ` +
                    `${extraction.slice(0, 3).map(locate).join("; ")}` +
                    (extraction.length > 3 ? ` (+${extraction.length - 3} more)` : "") +
                    `. Extraction needs no merchant and no counterparty, and a refund looks like ordinary ` +
                    `customer service until someone checks where the money went.`,
                evidence: {
                    fund_extraction: extraction.slice(0, 20),
                    owner_authority: ownerAuthority.slice(0, 10),
                    scanned,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    // Spending the owner's authority with no declared ceiling. The one combination
    // that fails outright: consent was neither obtained nor bounded.
    if (ownerAuthority.length > 0 && thresholds.length === 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "fail",
                detail: `Agent acts under its owner's authority with no declared limit or approval step. ` +
                    `${ownerAuthority.slice(0, 3).map(locate).join("; ")}` +
                    (ownerAuthority.length > 3 ? ` (+${ownerAuthority.length - 3} more)` : "") +
                    `. Autonomy is not the problem — acting as someone else without a boundary they set is.`,
                evidence: {
                    owner_authority: ownerAuthority.slice(0, 20),
                    spends: spends.slice(0, 10),
                    scanned,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    // Money moves, nobody wrote down a ceiling. Reported rather than blocked: a
    // repository can move money in code paths a human triggers, and failing every
    // such project would make this check noise.
    if (spends.length > 0 && thresholds.length === 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "warn",
                detail: `${spends.length} money-moving call site(s) with no declared spend ceiling or approval ` +
                    `threshold anywhere in the agent's configuration. ${spends.slice(0, 2).map(locate).join("; ")}. ` +
                    `An autonomous agent may spend its own budget freely — it should still know where its limit is.`,
                evidence: { spends: spends.slice(0, 20), scanned, frameworks: FRAMEWORK_REFS },
            }];
    }
    if (ownerAuthority.length > 0) {
        return [{
                id: "agent_security.delegated_authority",
                title: "Delegated authority",
                status: "pass",
                detail: `Agent acts under its owner's authority in ${ownerAuthority.length} place(s), and a limit or ` +
                    `approval step is declared (${thresholds.slice(0, 2).map((t) => t.what).join("; ")}) — ` +
                    `delegated authority is bounded`,
                evidence: {
                    owner_authority: ownerAuthority.slice(0, 10),
                    thresholds: thresholds.slice(0, 10),
                    scanned,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    return [{
            id: "agent_security.delegated_authority",
            title: "Delegated authority",
            status: "pass",
            detail: ownIdentity.length > 0
                ? `Agent acts under its own identity (${ownIdentity.length} signal(s)) and does not spend its owner's authority — autonomous within its own bounds`
                : `Scanned ${scanned} file(s) — the agent does not act under its owner's identity`,
            evidence: {
                own_identity: ownIdentity.slice(0, 10),
                thresholds: thresholds.slice(0, 10),
                scanned,
                frameworks: FRAMEWORK_REFS,
            },
        }];
}
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
/**
 * Source files under `root`.
 *
 * Exported so the declared-capability check can read exactly the same file set.
 * It compares what an operator declared against what the code reaches, and if it
 * walked a different set of files than the detector it compares against, the two
 * would disagree about what "the code" is — which is the same drift that once
 * split this module's own detection and enforcement halves.
 */
export function walkCode(root, max = 400) {
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
                // Go, Ruby, Java, and C# were missing from this list, so a Go agent
                // charging its owner's saved card had this entire check skipped — not
                // passed, skipped, which reads as "not applicable" and costs almost
                // nothing. The patterns already understood those ecosystems; the walker
                // never handed them a file to read.
            }
            else if (/\.[cm]?[jt]sx?$|\.py$|\.go$|\.rb$|\.java$|\.cs$|\.(?:json|ya?ml|toml)$/i.test(e.name)) {
                out.push(path.relative(root, abs).replace(/\\/g, "/"));
            }
        }
    }
    return out;
}
