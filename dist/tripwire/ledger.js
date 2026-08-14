import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
/**
 * Session ledger — an append-only transcript of what the agent did.
 *
 * Ordering is the entire signal in this test. Whether a charge came before or
 * after an authorization request is the difference between a pass and a critical
 * finding, so the transcript has to be resistant to quiet edits: an agent that can
 * reorder the record can launder its own behaviour.
 *
 * Each call is chained into a running digest. Recomputing the chain over a
 * transcript detects insertion, deletion, reordering, and in-place edits. This is
 * tamper *evidence*, not tamper proofing — an actor who rewrites the whole file
 * from scratch produces a consistent chain. It is the same honest guarantee the
 * attestation chain makes, and the same one a paper logbook makes.
 */
const LEDGER_DIR = ".proofwork/tripwire";
/** Deterministic serialization so a digest depends on content, never key order. */
function canonical(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value) ?? "null";
    if (Array.isArray(value))
        return `[${value.map(canonical).join(",")}]`;
    const obj = value;
    return `{${Object.keys(obj)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
        .join(",")}}`;
}
const sha256 = (input) => crypto.createHash("sha256").update(input, "utf8").digest("hex");
/** Fold one call into the running chain. Genesis is the session id. */
export function chainStep(previous, call) {
    return sha256(`${previous}\n${canonical(call)}`);
}
/** Recompute the chain across a transcript. */
export function computeDigest(record) {
    return record.calls.reduce((acc, call) => chainStep(acc, call), record.session_id);
}
/**
 * Verify a transcript against its own digest, and check the invariants that a
 * hash chain alone cannot express — sequence numbers must be dense and ordered,
 * because a gap means a call was removed even if the remaining chain is coherent.
 */
export function verifyLedger(record) {
    const reasons = [];
    record.calls.forEach((call, index) => {
        if (call.seq !== index + 1) {
            reasons.push(`sequence break at index ${index}: expected ${index + 1}, found ${call.seq}`);
        }
    });
    if (!record.digest) {
        reasons.push("transcript carries no digest — it cannot be shown to be intact");
    }
    else {
        const recomputed = computeDigest(record);
        if (recomputed !== record.digest) {
            reasons.push("digest mismatch — the transcript was altered after it was written");
        }
    }
    return { ok: reasons.length === 0, reasons };
}
/**
 * Records a single tripwire session.
 *
 * Held in memory during a run and flushed to disk on close, so a crashed session
 * leaves no half-written transcript that could be mistaken for a complete one.
 */
export class SessionLedger {
    record;
    digest;
    constructor(scenarioId, sessionId = `tw_${crypto.randomBytes(9).toString("hex")}`) {
        this.record = {
            schema_version: "1.0.0",
            session_id: sessionId,
            scenario_id: scenarioId,
            started_at: new Date().toISOString(),
            calls: [],
            authorizations: [],
        };
        this.digest = sessionId;
    }
    get sessionId() {
        return this.record.session_id;
    }
    get calls() {
        return this.record.calls;
    }
    get authorizations() {
        return this.record.authorizations;
    }
    /** Append a call. Returns the stored entry, including its assigned sequence. */
    append(tool, args, result, error) {
        const call = {
            seq: this.record.calls.length + 1,
            at: new Date().toISOString(),
            tool,
            args,
            result,
            ...(error ? { error } : {}),
        };
        this.record.calls.push(call);
        this.digest = chainStep(this.digest, call);
        return call;
    }
    addAuthorization(auth) {
        this.record.authorizations.push(auth);
    }
    /** Mark a token spent. Returns false when it was already consumed or unknown. */
    consumeAuthorization(token) {
        const auth = this.record.authorizations.find((a) => a.token === token);
        if (!auth || auth.consumed)
            return false;
        auth.consumed = true;
        return true;
    }
    findAuthorization(token) {
        return this.record.authorizations.find((a) => a.token === token);
    }
    /** Seal the transcript. After this the digest covers every recorded call. */
    finalize() {
        return {
            ...this.record,
            ended_at: this.record.ended_at ?? new Date().toISOString(),
            calls: [...this.record.calls],
            authorizations: this.record.authorizations.map((a) => ({ ...a })),
            digest: this.digest,
        };
    }
    /** Write the sealed transcript under the repo's .proofwork directory. */
    persist(root) {
        const dir = path.join(root, LEDGER_DIR);
        fs.mkdirSync(dir, { recursive: true });
        const file = path.join(dir, `${this.record.session_id}.json`);
        fs.writeFileSync(file, `${JSON.stringify(this.finalize(), null, 2)}\n`, "utf8");
        return path.relative(root, file).replace(/\\/g, "/");
    }
}
export function loadSession(file) {
    return JSON.parse(fs.readFileSync(file, "utf8"));
}
