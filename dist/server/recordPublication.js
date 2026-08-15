import { issuerPublicKey } from "../license.js";
import { readLog, verifyRegistryEntry, writeEntry } from "../registry.js";
/** Parse whatever arrived on the wire into an entry, or say why not. */
export function parseRecord(body) {
    let parsed;
    try {
        parsed = JSON.parse(body);
    }
    catch {
        return { ok: false, reason: "Body is not valid JSON." };
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, reason: "Expected a single record object." };
    }
    const entry = parsed;
    if (typeof entry.record_id !== "string" || !entry.record_id) {
        return { ok: false, reason: "Record has no record_id." };
    }
    return { ok: true, entry };
}
/**
 * Store a record, if we signed it and do not already have it.
 *
 * Verification comes first and decides everything. An entry that does not verify
 * is never written, so a malformed or forged submission cannot occupy an id that
 * a real record would later need.
 */
export function publishRecord(input) {
    const pub = input.publicKeyPem ?? issuerPublicKey();
    if (!pub) {
        return { status: "rejected", reason: "No issuer public key is configured; nothing can be checked." };
    }
    const verdict = verifyRegistryEntry(input.entry, pub);
    if (!verdict.ok) {
        // Expiry is deliberately not a reason to refuse. A record that has aged out
        // is still a true statement about what happened, and `/verify/:id` reports
        // the expiry itself — refusing to store it would make an old certificate
        // unverifiable rather than visibly old.
        const fatal = verdict.errors.filter((e) => !/expired/i.test(e));
        if (fatal.length > 0 || !verdict.expired) {
            return {
                status: "rejected",
                reason: `This record does not verify against the issuer key: ${verdict.errors.join("; ")}`,
            };
        }
    }
    const existing = readLog(input.logPath).find((r) => r.record_id === input.entry.record_id);
    if (existing) {
        // Idempotent. Publishing is a thing a customer may retry, and a second copy
        // would make the same record appear twice in any list built from this log.
        return { status: "already_published", entry: existing };
    }
    writeEntry(input.logPath, input.entry);
    return { status: "published", entry: input.entry };
}
