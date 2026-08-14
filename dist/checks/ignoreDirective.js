/**
 * The escape hatch, and its budget.
 *
 * An unlimited ignore directive is the gate's own off switch. An agent that has
 * read this repository can spray `// proofwork-ignore` across every line it
 * touches and pass with nothing examined — and unlike every other evasion, this
 * one requires no cleverness at all.
 *
 * The hatch still has to exist. A gate with no way to suppress a false positive
 * gets removed from the pipeline the first week it is wrong. So the rule is not
 * "no suppression", it is **suppression you have to account for**:
 *
 *   - A directive carrying a substantive reason is always honoured. Writing down
 *     why is the behaviour we want, and there is no reason to ration it.
 *   - A bare directive is honoured up to a small budget per file.
 *   - Past that budget, bare directives stop suppressing anything.
 *
 * A human silencing three findings is using the hatch. Forty is not suppression,
 * it is a decision to not be graded, and it should read as one.
 *
 * ## Why this is its own module
 *
 * Three checks now honour these directives. They lived inside `workmanship.ts`,
 * so `agentHijack.ts` had to import its suppression rules from an unrelated
 * check — layering that invites a fourth caller to write its own regex instead.
 * `testPaths.ts` exists because exactly that happened with the definition of a
 * test file, and two definitions drifted until a whole directory of tests went
 * unexamined. One definition cannot drift.
 */
const BARE_IGNORE_BUDGET = 3;
/** A reason long enough to be one. "// proofwork-ignore: x" is not a reason. */
const MIN_REASON_CHARS = 12;
const IGNORE_WITH_REASON = /proofwork-ignore(?:-next-line)?\s*[:—-]\s*(.+)$/i;
/** Any suppression directive, with or without a reason. */
export const IGNORE_BARE = /proofwork-ignore(?:-next-line)?\b/i;
/** Does this directive carry a substantive reason? */
export const hasReason = (line) => {
    const m = IGNORE_WITH_REASON.exec(line);
    return !!m && m[1].trim().length >= MIN_REASON_CHARS;
};
/**
 * How many bare directives this file is allowed to spend, given how many it used.
 * Computed once per file so the budget cannot be reset by interleaving them.
 */
export function bareIgnoreBudget(text) {
    const bare = text
        .split(/\r?\n/)
        .filter((l) => IGNORE_BARE.test(l) && !hasReason(l)).length;
    return bare > BARE_IGNORE_BUDGET ? 0 : BARE_IGNORE_BUDGET;
}
/** Per-file suppression state. Reason-carrying directives never consume budget. */
export class Suppression {
    budget;
    spent = 0;
    constructor(budget) {
        this.budget = budget;
    }
    allows(line, prev) {
        for (const candidate of [line, prev]) {
            if (!IGNORE_BARE.test(candidate))
                continue;
            // A next-line directive only applies from the previous line; an inline one
            // only from its own. Both forms appear in each slot, so accept either.
            if (hasReason(candidate))
                return true;
            if (this.spent < this.budget) {
                this.spent += 1;
                return true;
            }
            return false;
        }
        return false;
    }
}
/**
 * A reason is required — no bare-directive budget.
 *
 * For findings where silencing is a security decision rather than a false
 * positive. The value of the suppression is the sentence explaining why the line
 * is a demonstration rather than a capability; a bare directive records only that
 * somebody wanted the warning gone, which is not the same thing.
 */
export function suppressedWithReason(line, prev) {
    return [line, prev].some((c) => IGNORE_BARE.test(c) && hasReason(c));
}
