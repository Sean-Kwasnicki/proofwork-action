import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonical } from "./license.js";
import { keyIdFor } from "./registry.js";
/**
 * Revocation — withdrawing a record that has already been issued.
 *
 * ## Why a signed list rather than a lookup service
 *
 * `registry.ts` states the gap plainly: "Revocation needs a published list. Until
 * one exists, a leaked record stays verifiable." Until now the only mitigations
 * were expiry and commit-binding, which bound the damage without ending it — a
 * record issued in error, or against a repository whose key later leaked, stayed
 * good for up to a year.
 *
 * The list is **signed by the issuer**, and that is the load-bearing decision. An
 * unsigned list served from a URL is a list anyone who can serve that URL can
 * write, which means anyone who can intercept it can revoke a competitor's
 * certificate. Signing makes revocation an issuer-only act, exactly like issuance.
 *
 * ## Fail closed means something specific
 *
 * When a record appears on a list that verifies, it is REVOKED and no other
 * property rescues it — not a good signature, not an unexpired date. That is the
 * closed direction and it is absolute.
 *
 * It deliberately does **not** mean "refuse to verify when no list is present".
 * Offline verification against the embedded public key is a property this product
 * sells, and a verifier that demanded a network call before answering would put
 * our uptime in the middle of every customer's due-diligence conversation — the
 * exact dependency `verifyServer.ts` was written to avoid. With no list, a
 * verifier answers the question it can answer and says which question it could
 * not.
 *
 * ## The honest limitation
 *
 * An offline verifier holding a stale list can miss a recent revocation. This is
 * inherent to every revocation-list scheme, X.509 CRLs included, and no amount of
 * signing removes it. The list therefore carries `seq` and `next_update` so a
 * stale copy is *detectable*, and a checker that has a newer list must prefer it.
 * The hosted verify service always reads the issuer's current list, which is why
 * a link is the strongest check available and the CLI is the most independent
 * one. Both statements are true and they trade against each other.
 */
export const REVOCATION_SCHEMA = "proofwork.revocation/1";
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
export const REVOCATION_PATH = () => process.env.PROOFWORK_REVOCATION_LIST ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "revocations.json");
/** How long a published list is considered current. */
const DEFAULT_VALID_HOURS = 24;
function hashableBody(l) {
    return canonical(l);
}
/* ------------------------------------------------------------- issuing --- */
/**
 * Sign a revocation list.
 *
 * Entries are sorted by record id before hashing so that two publishes of the
 * same set produce the same hash regardless of the order they were added. A list
 * whose digest changed because of insertion order would make every republish look
 * like a content change to anyone diffing them.
 */
export function signRevocationList(entries, opts) {
    const now = opts.now ?? new Date();
    const validHours = opts.validHours ?? DEFAULT_VALID_HOURS;
    const base = {
        schema: REVOCATION_SCHEMA,
        seq: opts.seq,
        issued_at: now.toISOString(),
        next_update: new Date(now.getTime() + validHours * 3_600_000).toISOString(),
        entries: [...entries].sort((a, b) => a.record_id.localeCompare(b.record_id)),
        key_id: keyIdFor(opts.publicKeyPem),
    };
    const list_hash = sha256(hashableBody(base));
    const issuer_signature = crypto
        .sign(null, Buffer.from(list_hash, "utf8"), crypto.createPrivateKey(opts.privateKeyPem))
        .toString("base64url");
    return { ...base, list_hash, issuer_signature };
}
/** Verify a list's signature and freshness. Signature first; staleness is advisory. */
export function verifyRevocationList(list, publicKeyPem, now = Date.now()) {
    const errors = [];
    if (list.schema !== REVOCATION_SCHEMA) {
        return {
            ok: false,
            errors: [`Unknown revocation schema "${list.schema}" — this client is too old to read it.`],
            stale: false,
        };
    }
    const expectedKeyId = keyIdFor(publicKeyPem);
    if (list.key_id !== expectedKeyId) {
        errors.push(`List was signed by key ${list.key_id}, but verification used key ${expectedKeyId}.`);
    }
    const { list_hash, issuer_signature, ...base } = list;
    if (sha256(hashableBody(base)) !== list_hash) {
        errors.push("Revocation list contents do not match its hash — it was altered after signing.");
    }
    let sigOk = false;
    try {
        sigOk = crypto.verify(null, Buffer.from(list_hash, "utf8"), crypto.createPublicKey(publicKeyPem), Buffer.from(issuer_signature, "base64url"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk) {
        // An unsigned or wrongly-signed list is the dangerous case: accepting one
        // would let anybody who can place a file revoke anybody's certificate.
        errors.push("Revocation list signature does not verify — it was not published by Proofwork.");
    }
    return { ok: errors.length === 0, errors, stale: Date.parse(list.next_update) < now };
}
/**
 * Was this record withdrawn?
 *
 * A list that fails to verify is treated as no list at all rather than as an
 * empty one. Those look identical if you only ask "is the id present?", and the
 * difference matters: an attacker who can replace the list with garbage would
 * otherwise silently turn every revoked record back into a good one.
 */
export function revocationStatusFor(recordId, list, publicKeyPem, now = Date.now()) {
    if (!list) {
        return {
            revoked: false,
            checked: false,
            stale: false,
            note: "No revocation list was available, so this check could not run. The signature above " +
                "still verifies offline. For the current withdrawal status, open the verify link.",
        };
    }
    const verdict = verifyRevocationList(list, publicKeyPem, now);
    if (!verdict.ok) {
        return {
            revoked: false,
            checked: false,
            stale: verdict.stale,
            note: `Revocation list could not be trusted: ${verdict.errors.join(" ")}`,
        };
    }
    const entry = list.entries.find((e) => e.record_id === recordId);
    if (entry) {
        return {
            revoked: true,
            entry,
            checked: true,
            stale: verdict.stale,
            note: `Withdrawn on ${entry.revoked_at.slice(0, 10)}: ${entry.reason}`,
        };
    }
    return {
        revoked: false,
        checked: true,
        stale: verdict.stale,
        note: verdict.stale
            ? `Not withdrawn as of list #${list.seq}, issued ${list.issued_at.slice(0, 10)}. That list is ` +
                `past its refresh date, so a very recent withdrawal may not appear in it.`
            : `Not withdrawn as of list #${list.seq}, issued ${list.issued_at.slice(0, 10)}.`,
    };
}
/* ------------------------------------------------------------- storage --- */
export function readRevocationList(file = REVOCATION_PATH()) {
    try {
        return JSON.parse(fs.readFileSync(file, "utf8"));
    }
    catch {
        // Absent or unreadable. The caller distinguishes "no list" from "empty list".
        return null;
    }
}
/* ------------------------------------------------------- distribution --- */
/**
 * Fetch the published list, with a short in-process cache.
 *
 * The issuer and the verifier run as separate services on separate disks — the
 * verifier deliberately holds no key — so a list written by the issuer reaches
 * the verifier only if it is served. Without this, propagating a revocation would
 * require redeploying the verify service, and a revocation that takes a deploy is
 * not a revocation.
 *
 * Fetching over an untrusted channel is safe *because* the list is signed. A
 * hostile proxy can withhold it or corrupt it; both are detected, since a corrupt
 * list fails signature verification and is then treated as no list rather than as
 * an empty one. What no proxy can do is forge a withdrawal or erase one.
 *
 * Failure is never fatal. A verify request must still answer the question it can
 * answer — that is the whole design — so a fetch error degrades to "not checked"
 * rather than to an error page.
 */
let cache = null;
export const REVOCATION_CACHE_MS = 60_000;
export async function fetchRevocationList(url, opts = {}) {
    const now = opts.now ?? Date.now();
    if (cache && now - cache.at < REVOCATION_CACHE_MS)
        return cache.list;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 3_000);
    try {
        const res = await fetch(url, { signal: controller.signal });
        if (!res.ok)
            throw new Error(`HTTP ${res.status}`);
        const list = (await res.json());
        cache = { at: now, list };
        return list;
    }
    catch {
        // Cache the failure too, briefly. A verify service under load must not turn
        // one unreachable issuer into a fetch attempt per request.
        cache = { at: now, list: null };
        return null;
    }
    finally {
        clearTimeout(timer);
    }
}
/** Drop the cached list. Tests and `--republish` want the next read to be fresh. */
export function clearRevocationCache() {
    cache = null;
}
export function writeRevocationList(list, file = REVOCATION_PATH()) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(list, null, 2)}\n`, "utf8");
}
/**
 * Withdraw a record. Issuer-only — it needs the private key.
 *
 * Re-revoking is not an error and does not duplicate the entry. Revocation is a
 * state, not an event, and a support path that fails the second time somebody
 * runs it teaches people to check first and act second, which is backwards for
 * something you want done quickly.
 */
export function revokeRecord(opts) {
    const file = opts.file ?? REVOCATION_PATH();
    const current = readRevocationList(file);
    const entries = current?.entries ?? [];
    const existing = entries.find((e) => e.record_id === opts.recordId);
    if (existing) {
        return { list: current, alreadyRevoked: true };
    }
    const now = opts.now ?? new Date();
    const next = signRevocationList([...entries, { record_id: opts.recordId, revoked_at: now.toISOString(), reason: opts.reason }], {
        privateKeyPem: opts.privateKeyPem,
        publicKeyPem: opts.publicKeyPem,
        seq: (current?.seq ?? 0) + 1,
        now,
    });
    writeRevocationList(next, file);
    return { list: next, alreadyRevoked: false };
}
/**
 * Republish an unchanged list so its freshness window rolls forward.
 *
 * Without this, a list with no new revocations goes stale and every offline
 * checker starts reporting that it may be missing withdrawals — which trains
 * people to ignore the warning. Re-signing on a schedule is what keeps the stale
 * signal meaningful.
 */
export function republishRevocationList(opts) {
    const file = opts.file ?? REVOCATION_PATH();
    const current = readRevocationList(file);
    const next = signRevocationList(current?.entries ?? [], {
        privateKeyPem: opts.privateKeyPem,
        publicKeyPem: opts.publicKeyPem,
        seq: (current?.seq ?? 0) + 1,
        ...(opts.now ? { now: opts.now } : {}),
    });
    writeRevocationList(next, file);
    return next;
}
/** Rendered for an operator. */
export function renderRevocationList(list) {
    const rule = "─".repeat(74);
    if (!list) {
        return [
            "",
            "  REVOCATIONS",
            `  ${rule}`,
            "",
            "  No list has been published yet.",
            "",
            "  Publish an empty one with `proofwork revoke --republish` so checkers can",
            "  tell 'nothing is withdrawn' from 'nobody has said'.",
            "",
        ].join("\n");
    }
    return [
        "",
        "  REVOCATIONS",
        `  ${rule}`,
        "",
        `  List #${list.seq} · issued ${list.issued_at.slice(0, 16).replace("T", " ")}`,
        `  Refresh due ${list.next_update.slice(0, 16).replace("T", " ")}`,
        `  Signed by key ${list.key_id}`,
        "",
        ...(list.entries.length === 0
            ? ["  Nothing is withdrawn.", ""]
            : list.entries.map((e) => `  ${e.revoked_at.slice(0, 10)}  ${e.record_id}  ${e.reason}`)),
        "",
    ].join("\n");
}
