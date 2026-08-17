/**
 * What a signed record may be called in public.
 *
 * ## Why this is one function
 *
 * "Certified" appeared independently on the verify page, the ledger, the
 * certificate, the badge and the certificate email, and each surface decided for
 * itself — mostly by asking only whether the verdict was `pass`. A record that
 * passed the gate with 84/100 was therefore printed CERTIFIED by four of them
 * while the report card for the same run said PROVISIONAL.
 *
 * That is a headline disagreeing with its own mechanism, which is the failure
 * this product exists to detect, published under our name. Scoring rules will
 * move again; the describer has to be one function so they cannot drift apart a
 * second time.
 *
 * ## The rule
 *
 * A passing run is **Certified** at 85 and above, **Provisional** from 60 to 84.
 * A failing run is **Denied** whatever it scored.
 *
 * Provisional is a real, sellable outcome, not a euphemism for failure: the gate
 * passed, the record is signed, and it verifies. It says the work cleared the
 * blocking conditions without clearing the bar we are willing to put the word
 * "certified" behind — so a deposit under 85 is accepted and published, and
 * simply not called certified.
 */
/** The lowest score that may be described as certified. */
export const CERTIFIED_MIN = 85;
/** The lowest score a passing run may hold and still be published. */
export const PROVISIONAL_MIN = 60;
export function describeBand(input) {
    if (input.verdict !== "pass") {
        return {
            band: "denied",
            label: "DENIED",
            title: "Denied",
            certified: false,
            note: "The gate blocked this run. The record is signed and says so.",
        };
    }
    if (input.score >= CERTIFIED_MIN) {
        return {
            band: "certified",
            label: "CERTIFIED",
            title: "Certified",
            certified: true,
            note: `Passed the gate at ${input.score}/100, at or above the ${CERTIFIED_MIN} required to be called certified.`,
        };
    }
    return {
        band: "provisional",
        label: "PROVISIONAL",
        title: "Provisional",
        certified: false,
        // Stated as what it is rather than as a near-miss. The run genuinely passed.
        //
        // The word "certified" is deliberately absent even from this explanation. A
        // screenshot of a provisional record should not contain it anywhere, and a
        // sentence about the threshold reads as the label when it is cropped.
        note: `Passed the gate at ${input.score}/100. That clears every blocking condition but is ` +
            `below the ${CERTIFIED_MIN} required for the higher band, so it is published as provisional.`,
    };
}
