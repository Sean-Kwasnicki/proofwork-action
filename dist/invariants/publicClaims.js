/**
 * Public sentences that are illegal if they contradict the proof.
 *
 * On incorporate: `src/invariants/publicClaims.ts`.
 * Wire every surface that prints CERTIFIED / a score through `assertPublicClaims`.
 *
 * Thresholds live in `band.ts` — a second copy here is how CERTIFIED drifted
 * from the ledger once already.
 */
export { CERTIFIED_MIN, PROVISIONAL_MIN, } from "../band.js";
import { CERTIFIED_MIN, PROVISIONAL_MIN } from "../band.js";
export function bandFor(proofOk, earned, consentFail = false) {
    if (consentFail)
        return "denied";
    if (!proofOk)
        return earned >= PROVISIONAL_MIN ? "provisional" : "denied";
    if (earned >= CERTIFIED_MIN)
        return "certified";
    if (earned >= PROVISIONAL_MIN)
        return "provisional";
    return "denied";
}
export function assertPublicClaims(input) {
    const v = [];
    if (input.band === "certified") {
        if (!input.proofOk) {
            v.push({
                code: "certified_without_ok",
                detail: "CERTIFIED is illegal when proof.ok is false",
            });
        }
        if (input.earned < CERTIFIED_MIN) {
            v.push({
                code: "certified_below_bar",
                detail: `CERTIFIED requires earned >= ${CERTIFIED_MIN}, got ${input.earned}`,
            });
        }
    }
    if (!input.proofOk && input.band === "certified") {
        v.push({
            code: "refused_run_certified",
            detail: "A refused run cannot be certified",
        });
    }
    if (input.actionScore !== undefined && input.actionScore !== input.earned) {
        v.push({
            code: "action_score_drift",
            detail: `Action score ${input.actionScore} !== overall.earned ${input.earned}`,
        });
    }
    if (input.depositScore !== undefined && input.depositScore !== input.earned) {
        v.push({
            code: "deposit_score_drift",
            detail: `Deposit integrity_score ${input.depositScore} !== overall.earned ${input.earned}`,
        });
    }
    const expected = bandFor(input.proofOk, input.earned);
    if (input.band !== expected && input.band === "certified") {
        v.push({
            code: "band_mismatch",
            detail: `band ${input.band} disagrees with bandFor (${expected})`,
        });
    }
    return v;
}
export function claimsHold(input) {
    return assertPublicClaims(input).length === 0;
}
