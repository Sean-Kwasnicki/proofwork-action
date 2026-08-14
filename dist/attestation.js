import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
/**
 * Tamper-evident attestation chain (hash-linked + local HMAC).
 *
 * Honest limits (read before claiming "crypto ledger"):
 * - NOT a public blockchain
 * - NOT "unhackable" — anyone with the secret (or who rewrites a whole unpublished chain) can forge
 * - IS append-only with detectable in-place edits when verifiers have the chain file
 * - Long-term public legitimacy still needs independent publication / company countersign (future)
 */
const CHAIN_REL = ".proofwork/attestation.jsonl";
const SECRET_REL = ".proofwork/attest.secret";
function ensureSecret(root) {
    const p = path.join(root, SECRET_REL);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    if (!fs.existsSync(p)) {
        const secret = crypto.randomBytes(32);
        fs.writeFileSync(p, secret);
        try {
            fs.chmodSync(p, 0o600);
        }
        catch {
            // Windows has no POSIX permission bits, so `chmod` is a no-op or throws
            // depending on the filesystem. Failing here would make attestation
            // unusable on Windows to enforce a permission model that does not exist
            // there.
            //
            // The protection that actually matters is already in place: the file lives
            // outside the repository, so it cannot be committed by a stray `git add`.
            // Tightening the mode is a defence-in-depth step on platforms that have
            // one, not the thing keeping the secret out of version control.
        }
    }
    return fs.readFileSync(p);
}
function proofHash(proof) {
    const slim = {
        ok: proof.ok,
        integrity_score: proof.integrity_score,
        blockers: proof.blockers,
        summary: proof.summary,
        checks: proof.checks.map((c) => ({ id: c.id, status: c.status, detail: c.detail })),
        created_at: proof.created_at,
        issuer: proof.issuer,
    };
    return crypto.createHash("sha256").update(JSON.stringify(slim)).digest("hex");
}
function loadChain(root) {
    const p = path.join(root, CHAIN_REL);
    if (!fs.existsSync(p))
        return [];
    const lines = fs.readFileSync(p, "utf8").split(/\r?\n/).filter(Boolean);
    const out = [];
    for (const line of lines) {
        try {
            out.push(JSON.parse(line));
        }
        catch {
            throw new Error(`Corrupt attestation line (not JSON): ${line.slice(0, 80)}`);
        }
    }
    return out;
}
function canonicalForHash(e) {
    return JSON.stringify({
        schema_version: e.schema_version,
        seq: e.seq,
        at: e.at,
        product: e.product,
        tier: e.tier,
        ok: e.ok,
        integrity_score: e.integrity_score,
        seal: e.seal,
        proof_hash: e.proof_hash,
        brief: e.brief,
        prev_hash: e.prev_hash,
    });
}
export function appendAttestation(root, proof, cert, brief) {
    const secret = ensureSecret(root);
    const chain = loadChain(root);
    const prev = chain[chain.length - 1];
    const prev_hash = prev?.entry_hash ?? "genesis";
    const base = {
        schema_version: "0.1.0",
        seq: chain.length + 1,
        at: new Date().toISOString(),
        product: "Proofwork",
        tier: cert.tier,
        ok: cert.tier === "certified",
        integrity_score: cert.integrity_score,
        seal: cert.seal,
        proof_hash: proofHash(proof),
        brief: brief.slice(0, 500),
        prev_hash,
    };
    const entry_hash = crypto.createHash("sha256").update(canonicalForHash(base)).digest("hex");
    const mac = crypto.createHmac("sha256", secret).update(entry_hash).digest("hex");
    const entry = { ...base, entry_hash, mac };
    const p = path.join(root, CHAIN_REL);
    fs.appendFileSync(p, `${JSON.stringify(entry)}\n`, "utf8");
    return entry;
}
export function verifyAttestation(root, opts = {}) {
    const requireMac = opts.requireMac !== false;
    const errors = [];
    let chain = [];
    try {
        chain = loadChain(root);
    }
    catch (e) {
        return { ok: false, entries: 0, errors: [e instanceof Error ? e.message : String(e)] };
    }
    if (chain.length === 0) {
        return { ok: false, entries: 0, errors: ["No attestation chain yet — run proofwork certify"] };
    }
    let secret = null;
    const secretPath = path.join(root, SECRET_REL);
    if (fs.existsSync(secretPath))
        secret = fs.readFileSync(secretPath);
    let expectedPrev = "genesis";
    for (let i = 0; i < chain.length; i += 1) {
        const e = chain[i];
        if (e.seq !== i + 1)
            errors.push(`seq gap at index ${i}: expected ${i + 1}, got ${e.seq}`);
        if (e.prev_hash !== expectedPrev) {
            errors.push(`broken chain at seq ${e.seq}: prev_hash mismatch`);
        }
        const { entry_hash: _eh, mac: _m, ...rest } = e;
        const recomputed = crypto
            .createHash("sha256")
            .update(canonicalForHash(rest))
            .digest("hex");
        if (recomputed !== e.entry_hash) {
            errors.push(`entry_hash mismatch at seq ${e.seq} (payload tampered)`);
        }
        if (requireMac) {
            if (!secret)
                errors.push(`missing ${SECRET_REL} — cannot verify HMAC`);
            else {
                const mac = crypto.createHmac("sha256", secret).update(e.entry_hash).digest("hex");
                if (mac !== e.mac)
                    errors.push(`HMAC mismatch at seq ${e.seq}`);
            }
        }
        expectedPrev = e.entry_hash;
    }
    return {
        ok: errors.length === 0,
        entries: chain.length,
        errors,
        head: chain[chain.length - 1]?.entry_hash,
    };
}
export function attestationPublicSummary(root) {
    const chain = loadChain(root);
    if (!chain.length)
        return "No attestations yet.";
    const last = chain[chain.length - 1];
    const v = verifyAttestation(root, { requireMac: true });
    return [
        `Attestation chain: ${chain.length} entries`,
        `Head: ${last.entry_hash.slice(0, 16)}…`,
        `Latest: ${last.ok ? "CERTIFIED" : "DENIED"} seal=${last.seal} score=${last.integrity_score}`,
        `Verify: ${v.ok ? "OK (hash chain + local HMAC)" : "FAIL — " + v.errors[0]}`,
        "",
        "Note: tamper-evident local chain — not a public blockchain, not unhackable.",
    ].join("\n");
}
