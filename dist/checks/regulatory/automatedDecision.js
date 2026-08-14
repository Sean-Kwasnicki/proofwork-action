import { existsInTree, findLine, keyValue, matchesInCode, renderFinding, scanTree, } from "./shared.js";
/**
 * Automated decisions about people.
 *
 * ## The obligation
 *
 * GDPR Article 22 gives a person the right not to be subject to a decision based
 * *solely* on automated processing where that decision produces legal effects
 * concerning them or similarly significantly affects them. Where such processing
 * is permitted, Article 22(3) requires safeguards — at minimum the right to
 * obtain human intervention, to express a point of view, and to contest the
 * decision.
 *
 * The EU AI Act reaches the same place from the other side: Annex III lists
 * employment, creditworthiness, essential services, and law enforcement among
 * high-risk uses, and Article 14 requires those systems to be overseeable by a
 * human who can disregard or reverse the output.
 *
 * ## The word that does the work is "solely"
 *
 * An automated decision with a human review path is not an Article 22 decision.
 * That single word is the whole design of this check, and it is why the rule is
 * not "do not decide automatically" — deciding automatically is the point of the
 * software. The rule is: **if the decision lands on a person and has real
 * consequences, a human must be able to get in the way of it.**
 *
 * This matters more for agents than for the scoring systems Article 22 was
 * written about. A credit model produces a number that a workflow applies. An
 * autonomous agent decides *and executes*, closing the gap where review used to
 * live, usually without anyone choosing to remove it.
 *
 * ## What is actually checked
 *
 *   1. Does the code decide something *about a person* — credit, employment,
 *      insurance, benefits, account standing, pricing offered to an individual?
 *   2. Is the outcome applied automatically rather than proposed?
 *   3. Does any human review, appeal, override, or escalation path exist?
 *
 * A finding requires the first two and the absence of the third. Any one of them
 * alone is ordinary software.
 *
 * ## What is deliberately not claimed
 *
 * Whether a particular decision produces "legal or similarly significant
 * effects" is a judgement about context that no static rule can make, and this
 * check does not pretend to. It reports that a decision about a person appears to
 * execute with no review path in the repository, and names the article a reviewer
 * should read. The determination stays with the reviewer.
 */
const FRAMEWORK_REFS = {
    gdpr: ["Art. 22(1) Automated individual decision-making", "Art. 22(3) Right to human intervention"],
    eu: ["Art. 14 Human Oversight", "Annex III High-risk use cases"],
    iso42001: ["A.9.2 Responsible Use", "A.9.3 Objectives for Responsible Use"],
    nist: ["GOVERN 3.2", "MANAGE 2.4"],
};
/* ═════════════════════════ 1 — decisions that land on a person ═══ */
/**
 * Decision domains Article 22 and Annex III actually name.
 *
 * Anchored on named domains rather than on the word "decision", because software
 * decides constantly and almost none of it concerns a person's rights. A matcher
 * that flagged every branch would be indistinguishable from noise.
 */
const PERSONAL_DECISION = [
    { re: /\b(?:credit|loan|lending|underwrit\w*|creditworth\w*)[_.]?(?:score|decision|approval|limit|risk)\b|\b(?:approve|deny|reject)[_.]?(?:loan|credit|mortgage)\b/i, what: "creditworthiness decision" },
    { re: /\b(?:candidate|applicant|resume|cv|employment|hiring|recruit\w*)[_.]?(?:score|rank|screen|filter|reject|shortlist)\b|\bscreen[_.]?(?:candidate|applicant)s?\b/i, what: "employment or recruitment screening" },
    { re: /\b(?:insurance|premium|claim)[_.]?(?:decision|approval|denial|pricing|risk[_.]?score)\b|\b(?:approve|deny)[_.]?claim\b/i, what: "insurance or claims decision" },
    { re: /\b(?:benefit|welfare|eligibility|entitlement)[_.]?(?:decision|determination|assessment|denial)\b/i, what: "benefits or eligibility determination" },
    { re: /\b(?:fraud|risk|trust)[_.]?score\b[^\n]*\b(?:user|customer|account|person)\b|\b(?:user|account)[_.]?(?:risk|fraud)[_.]?score\b/i, what: "risk scoring applied to an individual" },
    { re: /\b(?:suspend|ban|terminate|deactivate|blacklist|restrict)[_.]?(?:user|account|member|seller|driver)\b/i, what: "account suspension or termination" },
    { re: /\b(?:personali[sz]ed|individual|dynamic)[_.]?pric(?:e|ing)\b/i, what: "individually targeted pricing" },
    { re: /\b(?:tenant|rental|housing|admission|enrol\w*)[_.]?(?:screen\w*|decision|approval)\b/i, what: "housing or admission decision" },
];
/* ═══════════════════════════ 2 — applied, not proposed ═══ */
/**
 * The outcome being enacted rather than surfaced for someone to act on.
 *
 * This is the line between a recommendation engine and an Article 22 decision.
 */
const AUTO_APPLIED = [
    { re: /\bauto[_.]?(?:approve|reject|deny|decline|suspend|ban|terminate|apply|execute|action)\w*\b/i, what: "outcome applied automatically" },
    { re: /\b(?:apply|execute|commit|enforce)[_.]?decision\b/i, what: "decision executed directly" },
    { re: /\bawait\s+(?:db|prisma|knex|repo\w*)\.[\w.]*update[^\n]*\bstatus\s*[:=]\s*["'](?:rejected|denied|approved|suspended|banned)["']/i, what: "decision written straight to the record" },
    { re: /\bstatus\s*[:=]\s*["'](?:auto[_-]?(?:approved|rejected|denied))["']/i, what: "record marked as automatically decided" },
];
/* ═════════════════════════ 3 — a human can intervene ═══ */
/**
 * Any route by which a person can get in the way of the outcome.
 *
 * Deliberately generous. Teams build this a dozen ways and call it a dozen
 * things; the obligation is that the route exists, not that it is spelled our
 * way. Being generous here means the check errs toward silence, which is the
 * correct direction for a rule whose false positive is an accusation.
 */
// No leading `\b`: the route is normally named `enqueueForHumanReview`, and a
// word boundary never fires between `r` and `H`. Anchoring on `\b` matched the
// snake_case fixtures and missed every camelCase application — the exact
// direction of error that produces false accusations against teams who complied.
const HUMAN_REVIEW = new RegExp([
    "human[\\s_.]?(?:review|intervention|oversight|approval)",
    "human[\\s_.]?in[\\s_.]?the[\\s_.]?loop",
    "manual[\\s_.]?(?:review|approval|override)",
    "second[\\s_.]?opinion",
    "requires?[\\s_.]?approval",
    "pending[\\s_.]?review",
    "awaiting[\\s_.]?(?:review|approval)",
    // Domain-named queues. A team that routes declines to its underwriters has
    // built the safeguard Art. 22(3) asks for, and calling it by the job title
    // rather than by the regulation's vocabulary must not be punished for it.
    "(?:underwriter|adjudicat|caseworker|analyst|agent|specialist|ops)\\w*[\\s_.]?queue",
    "(?:review|approval|escalation|exception)[\\s_.]?queue",
    "send[\\s_.]?to[\\s_.]?\\w*(?:underwriter|reviewer|human|agent|team)",
    "escalat",
    "appeal",
    "contest",
    "dispute",
    "override",
    "reviewer",
].join("|"), "i");
/** Explicit removal of a review path — a decision, not an omission. */
const REVIEW_REMOVED = [
    { re: /(?:skip|bypass|disable|remove)[_.]?(?:human[_.]?)?(?:review|appeal|oversight|approval)\w*/i, what: "human review path bypassed" },
    { re: keyValue("human[_.]?review|manual[_.]?review|appeal[_.]?(?:enabled|allowed)|oversight", "false|0|off|none"), what: "human review switched off in configuration" },
    { re: /\bno[_.]?(?:human|manual)[_.]?(?:review|intervention)\b/i, what: "review explicitly declared absent" },
];
/* ═══════════════════════════════════════════════════ entry ═══ */
export function scanAutomatedDecision(files) {
    const findings = [];
    const live = files.filter((f) => !f.isTestOrFixture);
    // A removed review path is reported wherever it appears, independent of
    // whether the decision domain is recognised — deliberately switching off
    // oversight is the finding, not a modifier of one.
    for (const f of live) {
        for (const rule of REVIEW_REMOVED) {
            const line = findLine(f.text, rule.re);
            if (line) {
                findings.push({
                    file: f.rel,
                    line,
                    article: "GDPR Art. 22(3)",
                    detail: `${rule.what} — a person subject to an automated decision has the right to obtain human intervention`,
                    severity: "hard",
                });
                break;
            }
        }
    }
    // Whether a review path exists is a property of the repository: a shared review
    // queue serves every decision that enqueues into it.
    const reviewPath = existsInTree(files, HUMAN_REVIEW);
    if (!reviewPath.found) {
        for (const f of live.filter((x) => x.isCode)) {
            const domain = PERSONAL_DECISION.find((r) => matchesInCode(f.text, r.re));
            if (!domain)
                continue;
            const applied = AUTO_APPLIED.find((r) => matchesInCode(f.text, r.re));
            if (!applied)
                continue;
            findings.push({
                file: f.rel,
                line: findLine(f.text, domain.re),
                article: "GDPR Art. 22(1)",
                detail: `${domain.what} where the ${applied.what.toLowerCase()}, and no human review, override, or ` +
                    `appeal path was found anywhere in this repository — the decision appears to rest solely on ` +
                    `automated processing`,
                severity: "hard",
            });
        }
    }
    return findings;
}
export function runAutomatedDecisionChecks(root) {
    const files = scanTree(root);
    if (files.length === 0) {
        return [{
                id: "regulatory.automated_decision",
                title: "Automated decisions about people (GDPR Art. 22)",
                status: "skip",
                detail: "No readable source files — nothing to assess",
                evidence: { scanned: 0, frameworks: FRAMEWORK_REFS },
            }];
    }
    const findings = scanAutomatedDecision(files);
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    const decidesAboutPeople = files.some((f) => !f.isTestOrFixture && f.isCode && PERSONAL_DECISION.some((r) => matchesInCode(f.text, r.re)));
    if (!decidesAboutPeople && findings.length === 0) {
        return [{
                id: "regulatory.automated_decision",
                title: "Automated decisions about people (GDPR Art. 22)",
                status: "skip",
                detail: `Scanned ${files.length} file(s) — this system does not appear to decide anything about an ` +
                    `individual's credit, employment, benefits, insurance, or account standing`,
                evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    if (hard.length > 0) {
        return [{
                id: "regulatory.automated_decision",
                title: "Automated decisions about people (GDPR Art. 22)",
                status: "fail",
                detail: `${hard.length} finding(s) — a decision affecting a person appears to execute with no way for ` +
                    `a human to intervene. ` +
                    hard.slice(0, 3).map(renderFinding).join("; ") +
                    (hard.length > 3 ? ` (+${hard.length - 3} more)` : ""),
                evidence: {
                    hard: hard.slice(0, 20),
                    soft: soft.slice(0, 10),
                    scanned: files.length,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    return [{
            id: "regulatory.automated_decision",
            title: "Automated decisions about people (GDPR Art. 22)",
            status: "pass",
            detail: `Scanned ${files.length} file(s) — decisions affecting individuals have a human review, override, ` +
                `or appeal path, so they do not rest solely on automated processing`,
            evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
        }];
}
