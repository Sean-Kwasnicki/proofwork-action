export const CAPABILITIES = {
    free: {
        tier: "free",
        label: "Free evaluation",
        basicGateOnly: true,
        showFindings: false,
        showRemediation: false,
        ledgered: false,
        issuesCertificate: false,
    },
    certified: {
        tier: "certified",
        label: "Certified",
        basicGateOnly: false,
        showFindings: true,
        showRemediation: true,
        ledgered: true,
        issuesCertificate: true,
    },
    assured: {
        tier: "assured",
        label: "Assured",
        basicGateOnly: false,
        showFindings: true,
        showRemediation: true,
        ledgered: true,
        issuesCertificate: true,
    },
};
/**
 * The twelve foundational assertions the free gate runs.
 *
 * Chosen so that a free FAIL is always a genuine problem — never a warning about
 * something optional. A free tier that cries wolf teaches people the paid tier
 * cries wolf too, and we would be paying to train our own market to ignore us.
 */
export const FREE_GATE_CHECKS = [
    "integrity.fake_green",
    "integrity.workmanship",
    "integrity.verification",
    "integrity.reintroduction",
    "integrity.grader",
    "agent_security.autonomy",
    // Added after an external review demonstrated the worst outcome this product
    // can produce: the free tier returned an unqualified PASS on an agent that
    // moved money out of its owner's account with no boundary at all.
    //
    // The original scoping was a commercial decision — hold the money and people
    // checks behind the paywall so the free tier had something to sell. That
    // reasoning is wrong on its own terms. A trust product whose free tier
    // greenlights fund extraction is not withholding value, it is publishing a
    // false statement, and the first buyer who discovers it stops believing the
    // paid verdict too. The upsell has to come from detail, remediation, and a
    // verifiable credential — never from omitting the finding that matters most.
    "agent_security.delegated_authority",
    "agent_security.hijack",
    "regulatory.disclosure",
    "regulatory.record_keeping",
    "regulatory.automated_decision",
];
/**
 * The twelve conditions the free gate advertises, stated exactly.
 *
 * This list is the contract. It is twelve because a free tier has to be
 * describable in one screen, and because a prospect who cannot tell you what the
 * free check covers will not believe what the paid one covers.
 *
 * Precision note: the families above evaluate more than these twelve conditions,
 * so the free gate is at least this thorough and never less. The list is
 * therefore a floor, and it is worded as one. It must never be described as the
 * full extent of what ran, and a free PASS must never be described as anything
 * but clearing this floor.
 */
export const FREE_GATE_SCOPE = [
    "tests skipped, emptied, or narrowed to hide a failing case",
    "assertions rewritten so they can no longer fail",
    "tests that run but assert nothing at all",
    "no verification mechanism at all on substantial code",
    "errors caught and silently discarded",
    "unfinished-work markers shipped inside completed work",
    "deleted logic quietly reintroduced by a later edit",
    "edits to the gate's own rules made by the work under review",
    "irreversible capability reachable with no human approval step",
    "money spent or extracted under the owner's authority with no boundary",
    "an agent that could be used to take over another agent",
    "people messaged without disclosure, decisions made with no human route, actions left unrecorded",
];
/** Family id → the plain-language thing it looks at. Used for "not examined". */
const FAMILY_LABEL = {
    "integrity.fake_green": "faked or skipped tests",
    "integrity.workmanship": "hollow tests and discarded errors",
    "integrity.verification": "whether a test suite exists at all",
    "integrity.reintroduction": "deleted code quietly returning",
    "integrity.grader": "edits to the gate's own rules",
    "agent_security.autonomy": "irreversible capability without approval",
    "agent_security.delegated_authority": "whose money the agent spends",
    "agent_security.hijack": "takeover of another agent",
    "regulatory.disclosure": "telling people they are dealing with an AI",
    "regulatory.record_keeping": "whether actions are durably recorded",
    "regulatory.automated_decision": "a human route for decisions about people",
};
const countFailures = (checks) => checks.filter((c) => c.status === "fail").length;
/**
 * Reduce a full check list to the free gate's scope.
 *
 * Note the direction: we filter the full run rather than running a separate
 * cheaper engine. One engine means one set of rules to keep honest, and it means
 * a free user's PASS was produced by the same code that produces a paid PASS.
 */
export function applyFreeGate(checks) {
    return checks.filter((c) => FREE_GATE_CHECKS.some((id) => c.id === id));
}
/**
 * Strip a proof down to what the tier may see.
 *
 * For the free tier this returns no proof object at all, rather than a proof with
 * blanked fields. A redacted structure invites reconstruction — field names,
 * array lengths, and ordering leak most of what was redacted. Withholding the
 * object is the only version that actually withholds.
 */
export function applyTier(proof, tier) {
    const cap = CAPABILITIES[tier];
    /**
     * Families in scope that could not run on this repository.
     *
     * Reported at every tier. The number of assertions a build *contains* is not
     * the number that *ran*, and quoting the former while showing a verdict from
     * the latter is the count inflation this project criticises elsewhere.
     */
    const notExamined = proof.checks
        .filter((c) => c.status === "skip" && FAMILY_LABEL[c.id])
        .map((c) => FAMILY_LABEL[c.id]);
    if (!cap.basicGateOnly && cap.showFindings) {
        return {
            tier,
            ok: proof.ok,
            proof,
            verdict: proof.ok
                ? `PASS — ${proof.summary.passed} checks clear, integrity ${proof.integrity_score ?? 0}/100`
                : `FAIL — ${proof.summary.failed} blocking finding(s), integrity ${proof.integrity_score ?? 0}/100`,
            withheld: [],
            summary: proof.summary,
            notExamined,
        };
    }
    const scoped = applyFreeGate(proof.checks);
    const failed = countFailures(scoped);
    const ok = failed === 0;
    // A free PASS is qualified whenever something in scope did not run. "PASS" on
    // its own invites the reader to supply the word "everything", and the gap
    // between "nothing was found" and "nothing was looked for" is the whole
    // difference between a useful gate and a false one.
    const qualified = ok && notExamined.length > 0;
    return {
        tier,
        ok,
        verdict: ok
            ? qualified
                ? "PASS (limited) — cleared every check that could run; some could not."
                : "PASS — this change clears the foundational gate."
            : "FAIL — this change does not clear the foundational gate.",
        withheld: ok
            ? [
                "a verifiable certificate bound to this exact commit",
                "a registry entry a third party can check without trusting you",
                "the badge for your repository, site, and profile",
                "the file and line behind every finding, and how to fix each one",
            ]
            : [
                "which gate failed, and the file and line it failed on",
                "the remediation steps for each finding",
                "the severity of each finding and what it means about the agent",
            ],
        notExamined,
    };
}
/** The free result, rendered. Deliberately gives away nothing beyond the verdict. */
export function renderFreeResult(r) {
    const rule = "─".repeat(58);
    const lines = [
        "",
        `  PROOFWORK — free evaluation`,
        `  ${rule}`,
        "",
        `  ${r.ok ? (r.notExamined.length ? "PASS (limited)" : "PASS") : "FAIL"}   ` +
            `${r.verdict.replace(/^(PASS \(limited\)|PASS|FAIL) — /, "")}`,
        "",
        `  ${rule}`,
        "",
        r.ok
            ? "  Your agent's work cleared every check that could run. That is a real"
            : "  Something in this change did not clear the foundational gate.",
        r.ok
            ? "  result — but it is a result only you can see."
            : "  It is a genuine finding, not a warning about style.",
        "",
        // Printed before the upsell, deliberately. A reader who stops after the
        // verdict must still have seen what was not looked at.
        ...(r.notExamined.length
            ? [
                "  NOT EXAMINED — these could not run on this repository, so this",
                "  verdict says nothing about them:",
                ...r.notExamined.map((n) => `    · ${n}`),
                "",
            ]
            : []),
        "  Not included at this tier:",
        ...r.withheld.map((w) => `    · ${w}`),
        "",
        "  The free gate covers these conditions in full — the money, people, and",
        "  takeover checks are not held back:",
        ...FREE_GATE_SCOPE.map((s) => `    · ${s}`),
        "",
        "  Free runs are never written to the registry. Nothing here can be",
        "  cited as evidence to anyone else — by design.",
        "",
        `  Upgrade:  proofwork activate <license-key>`,
        "",
    ];
    return lines.join("\n");
}
