/**
 * Where a verify link points.
 *
 * ## Why this is configurable rather than a constant
 *
 * Badges and certificates carry a link a third party is supposed to open. Baking
 * a hostname into the source means the day the service moves — or the day before
 * it exists — every artefact already issued points somewhere that does not
 * answer. A 404 on a verification link is worse than no link: it invites the
 * reader to conclude the certificate is fake, which is the opposite of what the
 * artefact is for.
 *
 * So the host comes from configuration, and the default is deliberately **not** a
 * domain that might resolve to somebody's parked page. Until an operator sets
 * `PROOFWORK_VERIFY_URL`, artefacts say plainly that no host is configured and
 * point the reader at the offline check, which needs no host at all.
 *
 * ## The offline path is always true
 *
 * `proofwork verify record.json` works with no network and no hostname. That is
 * the claim we can always make, so it is the one printed when the hosted link is
 * unavailable — rather than a link that may or may not resolve.
 */
/** Set by the operator at deploy: `https://verify.example.com`. */
export const VERIFY_HOST_ENV = "PROOFWORK_VERIFY_URL";
/** Trailing slashes and a `/verify` suffix are both easy to paste by mistake. */
function normaliseHost(raw) {
    return raw.trim().replace(/\/+$/, "").replace(/\/verify$/i, "");
}
export function verifyHost(env = process.env) {
    const raw = env[VERIFY_HOST_ENV];
    if (!raw || !raw.trim())
        return null;
    const host = normaliseHost(raw);
    // A host that is not a URL would produce a link that cannot be opened, which
    // is the failure this module exists to avoid.
    return /^https?:\/\/[^\s/]+/i.test(host) ? host : null;
}
export function verifyLinkFor(recordId, env = process.env) {
    const host = verifyHost(env);
    if (!host) {
        return {
            configured: false,
            url: null,
            instruction: `proofwork verify ${recordId}.json`,
        };
    }
    return {
        configured: true,
        url: `${host}/verify/${recordId}`,
        instruction: `${host}/verify/${recordId}`,
    };
}
