/**
 * Skip = duty not engaged. Skip never depresses the Certified ceiling.
 * A surface that could not be examined must warn or fail, not skip.
 *
 * Replaces the current `considered` mix of skips-inside-a-live-family that
 * pushed honest apps to Provisional (N/A theater).
 *
 * On incorporate: use `liveChecks` inside `scoreByCategory` when computing
 * coverageCap. Keep 55+45*ratio only over pass/fail/warn.
 */
export const CERTIFIED_MIN = 85;
export function liveChecks(checks) {
    return checks.filter((c) => c.status !== "skip");
}
export function coverageCap(examined, considered) {
    if (considered <= 0)
        return 0;
    const ratio = examined / considered;
    return Math.round(55 + 45 * ratio);
}
/** Coverage over live checks only. All-skip repo → cap 0 (nothing cleared). */
export function coverageFromChecks(checks) {
    const live = liveChecks(checks);
    const examined = live.length;
    const considered = live.length;
    return { examined, considered, cap: coverageCap(examined, considered) };
}
export function bandAfterCeiling(opts) {
    if (opts.blockingFails > 0 || !opts.proofOk) {
        return opts.earned >= 60 ? "provisional" : "denied";
    }
    if (opts.earned >= CERTIFIED_MIN)
        return "certified";
    if (opts.earned >= 60)
        return "provisional";
    return "denied";
}
