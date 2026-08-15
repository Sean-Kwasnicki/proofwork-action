/**
 * Reduce a proof to the deposit.
 *
 * Constructed field by field rather than by copying the proof and deleting
 * things. A deny-list would ship any field a later version of `Proof` happened
 * to add; this ships only what is named here.
 */
export function buildDepositPayload(input) {
    const commit = input.commit ?? input.proof.binding?.commit ?? input.proof.repo.commit ?? "";
    return {
        subject: input.subject,
        verdict: input.proof.ok ? "pass" : "fail",
        integrity_score: input.score,
        assertions: input.assertions,
        summary: {
            passed: input.proof.summary.passed,
            failed: input.proof.summary.failed,
            warned: input.proof.summary.warned,
            skipped: input.proof.summary.skipped,
        },
        commit,
        tree_digest: input.proof.binding?.tree_digest ?? "",
        repository: input.repository,
        ...(input.branch ? { branch: input.branch } : {}),
        ...(input.proof.schema_version ? { engine_version: input.proof.schema_version } : {}),
    };
}
/**
 * Ask GitHub for an OIDC token naming this job.
 *
 * The two variables are injected by Actions only when the job declares
 * `permissions: id-token: write`. Their absence is the single most likely
 * misconfiguration, so it is reported as that rather than as a network error.
 *
 * The audience must be the issuer's own URL. GitHub will mint a token for any
 * audience asked for, and one naming somebody else is useless here — by design,
 * since that is what stops a token minted for another service being replayed
 * against us.
 */
export async function requestOidcToken(input) {
    const env = input.env ?? process.env;
    const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!url || !bearer) {
        return {
            ok: false,
            reason: "No OIDC token is available to this job. The workflow needs:\n\n" +
                "    permissions:\n      id-token: write\n\n" +
                "Without it GitHub cannot attest which workflow produced this result, and " +
                "a score nobody can attribute is not one we will sign.",
        };
    }
    const doFetch = input.fetchImpl ?? fetch;
    try {
        const res = await doFetch(`${url}&audience=${encodeURIComponent(input.audience)}`, {
            headers: { authorization: `Bearer ${bearer}` },
            signal: AbortSignal.timeout(15_000),
        });
        if (!res.ok)
            return { ok: false, reason: `GitHub returned HTTP ${res.status} for the OIDC token.` };
        const body = (await res.json());
        if (!body.value)
            return { ok: false, reason: "GitHub returned no token value." };
        return { ok: true, token: body.value };
    }
    catch (e) {
        return { ok: false, reason: `Could not obtain an OIDC token: ${e instanceof Error ? e.message : String(e)}` };
    }
}
/** POST the deposit. The licence travels in a header, never in the body or a log. */
export async function sendDeposit(input) {
    const doFetch = input.fetchImpl ?? fetch;
    const base = input.issuerUrl.replace(/\/+$/, "");
    try {
        const res = await doFetch(`${base}/deposit`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${input.oidcToken}`,
                "x-proofwork-license": input.licenceKey,
            },
            body: JSON.stringify(input.payload),
            signal: AbortSignal.timeout(30_000),
        });
        const body = (await res.json().catch(() => ({})));
        if (!res.ok) {
            return { ok: false, reason: body.reason ?? `The issuer returned HTTP ${res.status}.` };
        }
        return {
            ok: true,
            status: body.status ?? "issued",
            recordId: body.record_id ?? "",
            verifyUrl: `${base}${body.verify_path ?? ""}`,
        };
    }
    catch (e) {
        return { ok: false, reason: `Could not reach the issuer: ${e instanceof Error ? e.message : String(e)}` };
    }
}
