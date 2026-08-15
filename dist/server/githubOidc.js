import crypto from "node:crypto";
/**
 * Verifying a GitHub Actions OIDC token.
 *
 * ## What this is actually for
 *
 * The issuer signs a score it did not compute. Something has to make that
 * defensible, and a licence key cannot: a licence proves someone paid, not that
 * the number they are sending is real. A paying customer could POST
 * `integrity_score: 100` for a repository that never ran a check.
 *
 * GitHub signs a token describing the job that is running — which repository,
 * which commit, and crucially **which workflow file**. If that workflow is ours,
 * the grading was done by code we published and the customer cannot edit. That
 * claim, not the licence, is what makes the score signable.
 *
 * So `job_workflow_ref` is the load-bearing field, and the caller checks it.
 * This module's job is to establish that the token is genuinely GitHub's and has
 * not been tampered with, so the claims can be trusted at all.
 *
 * ## The attacks this has to survive
 *
 * **Algorithm confusion.** A JWT header names its own algorithm, so a verifier
 * that trusts it can be handed `alg: "none"` — or `HS256` with the public key as
 * the HMAC secret, which verifies against a key the attacker already has. The
 * algorithm is therefore pinned to RS256 here and the header's claim is only
 * ever compared against it, never followed.
 *
 * **Wrong audience.** GitHub will mint a token for any audience a workflow asks
 * for, including one naming somebody else's service. A token minted for
 * `https://example.com` is a valid GitHub token and must not be accepted here,
 * or any repository on GitHub could deposit against us by asking for the wrong
 * audience and replaying it.
 *
 * **A key we have never seen.** `kid` selects the signing key from GitHub's
 * published set. An unknown `kid` is refused rather than treated as a reason to
 * skip verification.
 *
 * ## No dependency
 *
 * This project ships with no runtime dependencies, and a JWT library on the box
 * that holds the signing key is a large amount of code to audit for something
 * Node's own crypto does. `createPublicKey` accepts a JWK directly.
 */
export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${GITHUB_ISSUER}/.well-known/jwks`;
/** Only RS256. Never read from the token. */
const ALG = "RS256";
/** Clocks drift between GitHub and a container. Small, and applied both ways. */
const SKEW_SECONDS = 60;
/**
 * GitHub's published keys, cached briefly.
 *
 * Cached because a deposit should not wait on a second round trip, and briefly
 * because GitHub rotates: a long cache would reject every token signed with a
 * new key until the process restarted. On a cache miss for an unknown `kid` the
 * cache is refreshed once before giving up, so a rotation costs one extra fetch
 * rather than an outage.
 */
const CACHE_MS = 10 * 60 * 1000;
let cache = null;
/** Exposed so tests start from a known state rather than inheriting one. */
export function clearJwksCache() {
    cache = null;
}
const defaultFetcher = async () => {
    const res = await fetch(JWKS_URL, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok)
        throw new Error(`JWKS fetch returned HTTP ${res.status}`);
    return (await res.json());
};
async function keysFor(kid, fetcher, now) {
    const fresh = cache && now - cache.at < CACHE_MS;
    if (fresh) {
        const hit = cache.keys.find((k) => k.kid === kid);
        if (hit)
            return hit;
    }
    const jwks = await fetcher();
    cache = { at: now, keys: jwks.keys ?? [] };
    return cache.keys.find((k) => k.kid === kid) ?? null;
}
const decodeSegment = (seg) => JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
/**
 * Verify a token and return its claims.
 *
 * Every failure returns a reason rather than throwing, because the caller turns
 * these into HTTP responses and an operator reading a 401 needs to know whether
 * the token was expired, for the wrong audience, or not GitHub's at all.
 */
export async function verifyGithubOidc(input) {
    const now = Math.floor((input.now ?? Date.now()) / 1000);
    const token = (input.token ?? "").trim();
    const parts = token.split(".");
    if (parts.length !== 3)
        return { ok: false, reason: "Not a JWT — expected three dot-separated segments." };
    let header;
    let claims;
    try {
        header = decodeSegment(parts[0]);
        claims = decodeSegment(parts[1]);
    }
    catch {
        return { ok: false, reason: "Token header or body is not valid base64url JSON." };
    }
    // Pinned, never followed. `alg: none` and an HS256 token signed with the
    // public key both die here.
    if (header.alg !== ALG) {
        return { ok: false, reason: `Unexpected token algorithm ${String(header.alg)}; only ${ALG} is accepted.` };
    }
    if (!header.kid)
        return { ok: false, reason: "Token header names no key id." };
    if (claims.iss !== GITHUB_ISSUER) {
        return { ok: false, reason: `Token issuer ${String(claims.iss)} is not GitHub Actions.` };
    }
    // GitHub mints tokens for whatever audience a workflow asks for, including
    // one naming someone else. Accepting a foreign audience would let any
    // repository on GitHub deposit against us.
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(input.audience)) {
        return {
            ok: false,
            reason: `Token audience ${JSON.stringify(claims.aud)} is not ${input.audience}.`,
        };
    }
    if (typeof claims.exp !== "number" || claims.exp + SKEW_SECONDS < now) {
        return { ok: false, reason: "Token has expired." };
    }
    if (typeof claims.nbf === "number" && claims.nbf - SKEW_SECONDS > now) {
        return { ok: false, reason: "Token is not valid yet." };
    }
    let jwk;
    try {
        jwk = await keysFor(header.kid, input.fetchJwks ?? defaultFetcher, input.now ?? Date.now());
    }
    catch (e) {
        // Distinguished from a bad token on purpose: this is our problem, not the
        // caller's, and the caller should retry rather than change anything.
        return { ok: false, reason: `Could not reach GitHub's key set: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!jwk)
        return { ok: false, reason: `No GitHub signing key matches key id ${header.kid}.` };
    let verified = false;
    try {
        const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
        verified = crypto.verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"), { key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(parts[2], "base64url"));
    }
    catch (e) {
        return { ok: false, reason: `Token signature could not be checked: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!verified)
        return { ok: false, reason: "Token signature does not verify against GitHub's key." };
    return { ok: true, claims };
}
/**
 * Does this token come from the workflow we publish?
 *
 * `job_workflow_ref` names the workflow file that is executing. In a reusable
 * workflow that is *ours* even though the run belongs to the customer, which is
 * exactly the property being relied on: the customer controls the repository and
 * the code being graded, and does not control the grading.
 *
 * The comparison is anchored at both ends. A prefix match alone would accept
 * `evil/proofwork-action-fake/...`, and matching the file without the owner
 * would accept anyone who named their workflow `gate.yml`.
 */
export function isOfficialWorkflow(jobWorkflowRef, expected = OFFICIAL_WORKFLOW) {
    if (!jobWorkflowRef)
        return false;
    const at = jobWorkflowRef.lastIndexOf("@");
    // Any ref is allowed — v1, a tag, a SHA — but the path must be exact.
    const path = at === -1 ? jobWorkflowRef : jobWorkflowRef.slice(0, at);
    return path === expected;
}
/** The reusable workflow whose runs may mint a public record. */
export const OFFICIAL_WORKFLOW = "Sean-Kwasnicki/proofwork-action/.github/workflows/gate.yml";
