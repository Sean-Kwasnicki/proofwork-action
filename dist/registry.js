import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonical } from "./license.js";
/**
 * The Proofwork registry — the issuer-signed ledger.
 *
 * ## The problem this exists to fix
 *
 * The attestation chain in `attestation.ts` is hash-linked and MAC'd, which
 * sounds strong and is nearly worthless for the thing customers want to do with
 * it. It lives inside the customer's repository, and its HMAC secret is generated
 * on the customer's machine. Anyone holding that secret can rewrite the entire
 * chain and re-MAC it, and the holder is by construction the party whose claim is
 * being checked.
 *
 * So it answers "has this file been edited since I wrote it?" — useful locally —
 * and cannot answer "did this company actually pass?", which is the question a
 * buyer, an insurer, or an acquirer is asking. A ledger whose author is the party
 * making the claim is a diary.
 *
 * ## What changes here
 *
 * Registry entries are signed with a key only the issuer holds. A customer can
 * present a record; they cannot manufacture one. Verification needs the issuer's
 * public key and nothing else — no call to us, no account, no trust in the
 * presenter. That is the property that makes a certificate worth paying for.
 *
 * ## Honest limits, stated because a security claim without limits is marketing
 *
 * - Signing proves *we issued this record*. It does not prove the customer's
 *   software is safe, and no signature could.
 * - Anyone holding the issuer private key can mint entries. Protecting that key
 *   is the whole security model; there is no clever protocol that removes it.
 * - Revocation needs a published list. Until one exists, a leaked record stays
 *   verifiable, so entries carry an expiry and are scoped to one commit.
 * - This is a signed append-only log, not a blockchain. There is no distributed
 *   consensus and we do not claim any. Calling it a blockchain would be the exact
 *   kind of overstatement this product exists to catch.
 */
export const REGISTRY_SCHEMA = "proofwork.registry/1";
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
/** Digest of the parts of a proof that constitute the claim. */
export function proofDigest(proof) {
    return sha256(canonical({
        ok: proof.ok,
        integrity_score: proof.integrity_score,
        summary: proof.summary,
        binding: proof.binding ?? null,
        checks: proof.checks.map((c) => ({ id: c.id, status: c.status })),
    }));
}
/** Short, unambiguous, and safe to read aloud — no 0/O or 1/l confusion. */
function mintRecordId(seed) {
    const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    const digest = crypto.createHash("sha256").update(seed).digest();
    let out = "";
    for (let i = 0; i < 12; i += 1)
        out += alphabet[digest[i] % alphabet.length];
    return `PW-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}`;
}
export function keyIdFor(publicKeyPem) {
    return sha256(publicKeyPem.replace(/\s+/g, "")).slice(0, 16);
}
function hashableBody(e) {
    return canonical(e);
}
/**
 * Append a signed entry to a registry log.
 *
 * Takes the existing log rather than a path so the caller decides where the log
 * lives — a file today, a database row when there is a service. The signing and
 * chaining rules are the part that must not vary with storage.
 */
export function appendRegistryEntry(log, opts) {
    const prev = log[log.length - 1];
    const now = new Date();
    const validDays = opts.validDays ?? 365;
    const expires = new Date(now.getTime() + validDays * 86_400_000);
    const digest = proofDigest(opts.proof);
    const base = {
        schema: REGISTRY_SCHEMA,
        record_id: mintRecordId(`${digest}:${prev?.entry_hash ?? "genesis"}:${now.toISOString()}`),
        seq: (prev?.seq ?? 0) + 1,
        issued_at: now.toISOString(),
        expires_at: expires.toISOString(),
        subject: opts.subject,
        tier: opts.tier,
        verdict: opts.proof.ok ? "pass" : "fail",
        integrity_score: opts.proof.integrity_score ?? 0,
        assertions: opts.assertions,
        commit: opts.proof.repo.commit,
        tree_digest: opts.proof.binding?.tree_digest ?? null,
        proof_digest: digest,
        prev_hash: prev?.entry_hash ?? "genesis",
        key_id: keyIdFor(opts.publicKeyPem),
    };
    const entry_hash = sha256(hashableBody(base));
    const issuer_signature = crypto
        .sign(null, Buffer.from(entry_hash, "utf8"), crypto.createPrivateKey(opts.privateKeyPem))
        .toString("base64url");
    return { ...base, entry_hash, issuer_signature };
}
/**
 * Verify a single record against the issuer's public key.
 *
 * This is what a third party runs. It needs the record and the public key —
 * nothing from the customer, and no network call to us. If verifying required
 * asking us, we would be a single point of failure for every claim we ever
 * issued, and every buyer's due diligence would stall on our uptime.
 */
export function verifyRegistryEntry(entry, publicKeyPem) {
    const errors = [];
    if (entry.schema !== REGISTRY_SCHEMA) {
        errors.push(`Unknown record schema "${entry.schema}" — this client is too old to verify it.`);
        return { ok: false, errors, expired: false };
    }
    const expectedKeyId = keyIdFor(publicKeyPem);
    if (entry.key_id !== expectedKeyId) {
        errors.push(`Record was signed by key ${entry.key_id}, but verification used key ${expectedKeyId}.`);
    }
    const { entry_hash, issuer_signature, ...base } = entry;
    const recomputed = sha256(hashableBody(base));
    if (recomputed !== entry_hash) {
        errors.push("Record contents do not match its hash — a field was altered after issuance.");
    }
    let sigOk = false;
    try {
        sigOk = crypto.verify(null, Buffer.from(entry_hash, "utf8"), crypto.createPublicKey(publicKeyPem), Buffer.from(issuer_signature, "base64url"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk)
        errors.push("Issuer signature does not verify — this record was not issued by Proofwork.");
    const expired = Date.parse(entry.expires_at) < Date.now();
    if (expired) {
        errors.push(`Record expired on ${entry.expires_at.slice(0, 10)} — it needs to be re-earned.`);
    }
    return { ok: errors.length === 0, errors, expired };
}
/**
 * Verify a whole log: every signature, and the chain between them.
 *
 * Per-entry signatures alone would let the issuer — or anyone who obtained the
 * file — drop an inconvenient entry without trace. The chain makes a deletion
 * show up as a break, which matters most when the party who might want to delete
 * something is us.
 */
export function verifyRegistryLog(log, publicKeyPem) {
    const errors = [];
    let expectedPrev = "genesis";
    for (let i = 0; i < log.length; i += 1) {
        const e = log[i];
        const r = verifyRegistryEntry(e, publicKeyPem);
        // An expired record is still authentic; only its currency lapsed. Reporting
        // that as log corruption would send people hunting a tampering incident that
        // did not happen.
        for (const err of r.errors) {
            if (!err.startsWith("Record expired"))
                errors.push(`seq ${e.seq}: ${err}`);
        }
        if (e.seq !== i + 1)
            errors.push(`seq ${e.seq}: out of order — expected ${i + 1}`);
        if (e.prev_hash !== expectedPrev) {
            errors.push(`seq ${e.seq}: chain broken — an earlier entry was removed or altered`);
        }
        expectedPrev = e.entry_hash;
    }
    return { ok: errors.length === 0, errors, entries: log.length };
}
/* ------------------------------------------------------------- storage --- */
export function readLog(file) {
    if (!fs.existsSync(file))
        return [];
    return fs
        .readFileSync(file, "utf8")
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line, i) => {
        try {
            return JSON.parse(line);
        }
        catch {
            throw new Error(`Registry log line ${i + 1} is not valid JSON.`);
        }
    });
}
export function writeEntry(file, entry) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `${JSON.stringify(entry)}\n`, "utf8");
}
