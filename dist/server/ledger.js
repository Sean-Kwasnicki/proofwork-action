import { describeBinding } from "../bundle.js";
import { issuerPublicKey } from "../license.js";
import { readLog, verifyRegistryEntry } from "../registry.js";
import { readRevocationList, revocationStatusFor } from "../revocation.js";
/**
 * Build the rows.
 *
 * Every entry is re-verified rather than trusted because it is in the file. The
 * log on this host is a distribution mirror written by an endpoint anyone can
 * post to; the endpoint checks signatures, but a list that only re-read what it
 * had already accepted would carry a whole class of problem — a corrupted file,
 * a partial write, a key rotation — straight onto a public page as "certified".
 */
export function ledgerRows(opts) {
    const pub = opts.publicKeyPem ?? issuerPublicKey();
    if (!pub)
        return [];
    const now = opts.now ?? Date.now();
    const revocations = readRevocationList(opts.revocationPath);
    let entries;
    try {
        entries = readLog(opts.logPath);
    }
    catch {
        // An unreadable log is an empty ledger, not a crash. The page says "nothing
        // published yet", which is wrong but harmless; inventing rows would not be.
        return [];
    }
    const wanted = opts.organization?.trim().toLowerCase();
    return entries
        .filter((e) => e.verdict === "pass")
        .filter((e) => !wanted || e.subject.trim().toLowerCase() === wanted)
        .filter((e) => {
        const v = verifyRegistryEntry(e, pub);
        // `expired` is not a reason to drop it — the signature is still good and
        // the row says so. Anything else failing means this is not a record we
        // are prepared to vouch for in public.
        return v.ok || (v.expired && v.errors.every((m) => /expired/i.test(m)));
    })
        .filter((e) => !revocationStatusFor(e.record_id, revocations, pub, now).revoked)
        .map((e) => {
        const bound = describeBinding(e);
        return {
            record_id: e.record_id,
            date: e.issued_at.slice(0, 10),
            organization: e.subject,
            score: e.integrity_score,
            bound_label: bound.label,
            bound_short: bound.short,
            expired: Date.parse(e.expires_at) < now,
            verify_path: `/verify/${e.record_id}`,
        };
    })
        .sort((a, b) => (a.date === b.date ? a.record_id.localeCompare(b.record_id) : b.date.localeCompare(a.date)));
}
export function ledgerPayload(opts) {
    const records = ledgerRows(opts);
    return {
        schema: "proofwork.ledger/1",
        generated_at: new Date(opts.now ?? Date.now()).toISOString(),
        count: records.length,
        records,
        note: "Certified records only. Denied records are signed and given to their holder, " +
            "and are not published here. Each row can be checked independently at its verify " +
            "link, or offline with the record file and no network.",
    };
}
