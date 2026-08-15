import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { issueCredential } from "../credential.js";
import { verifyLicense } from "../license.js";
import { readLog } from "../registry.js";
import { isOfficialWorkflow, verifyGithubOidc, OFFICIAL_WORKFLOW, } from "./githubOidc.js";
/**
 * Turning a CI run into a signed record, with nobody at Proofwork involved.
 *
 * ## The problem in one sentence
 *
 * We sign a score we did not compute.
 *
 * Everything here exists to make that defensible. A licence proves somebody
 * paid; it says nothing about whether the number they are sending is real, and a
 * paying customer could otherwise POST `integrity_score: 100` for a repository
 * that never ran a check. Signing that would make the certificate worthless and
 * would make us the thing this product exists to detect.
 *
 * So the score is only signed when GitHub attests that **our** reusable workflow
 * produced it. `job_workflow_ref` in the OIDC token names the workflow file that
 * is executing, and in a reusable workflow that is ours even though the run
 * belongs to the customer. The customer controls the code being graded and does
 * not control the grading.
 *
 * Both credentials are required and neither is sufficient:
 *
 *   OIDC alone   — proves our workflow ran, not that anyone paid.
 *   licence alone — proves someone paid, not that any grading happened.
 *
 * ## Hash-only
 *
 * No source, no diffs, no findings, no file names. The deposit carries a
 * verdict, counts, a score, and the digests the record binds to. Customer code
 * never reaches our disk, which is a promise on the site and is enforced here by
 * refusing a payload that carries source-shaped fields rather than by trusting
 * the client not to send them.
 */
/** Audience the workflow must request. Anything else is somebody else's token. */
export const DEPOSIT_AUDIENCE = "https://proofwork-issuer.onrender.com";
/**
 * Fields that would mean source or findings had been sent.
 *
 * Rejected rather than stripped. Silently dropping them would let a future
 * version of the workflow start sending code without anyone noticing that the
 * "we never receive your source" claim had stopped being true.
 */
const FORBIDDEN_FIELDS = [
    "checks",
    "findings",
    "diff",
    "patch",
    "files",
    "source",
    "content",
    "blobs",
    "report",
    "remediation",
];
const DEPOSIT_LOG = () => process.env.PROOFWORK_DEPOSIT_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "deposits.jsonl");
export function readDeposits(logPath = DEPOSIT_LOG()) {
    try {
        return fs
            .readFileSync(logPath, "utf8")
            .split(/\r?\n/)
            .filter(Boolean)
            .map((l) => JSON.parse(l));
    }
    catch {
        return [];
    }
}
/**
 * One record per licence, commit and repository.
 *
 * A workflow re-run is normal — a flaky network step, a maintainer pressing the
 * button — and each one produces a fresh OIDC token, so nothing upstream stops a
 * second deposit. Without this key, one merge would mint several certificates
 * for the same commit and the ledger would show an organisation apparently
 * passing four times in a minute.
 *
 * Keyed on the licence rather than the organisation name so two licences for the
 * same customer stay distinguishable, and hashed so the log does not carry a
 * licence id in the clear.
 */
function idempotencyKey(jti, repository, commit) {
    return crypto.createHash("sha256").update(`${jti}\n${repository}\n${commit}`).digest("hex").slice(0, 32);
}
/* ---------------------------------------------------------- the policy --- */
function parsePayload(body) {
    let raw;
    try {
        raw = JSON.parse(body);
    }
    catch {
        return { ok: false, reason: "Body is not valid JSON." };
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return { ok: false, reason: "Expected a single deposit object." };
    }
    const obj = raw;
    const present = FORBIDDEN_FIELDS.filter((f) => obj[f] !== undefined);
    if (present.length > 0) {
        return {
            ok: false,
            reason: `Deposit carries ${present.join(", ")}. This endpoint takes hashes and counts only — ` +
                `customer source and findings must not leave the customer's runner.`,
        };
    }
    const p = obj;
    const missing = ["subject", "verdict", "commit", "tree_digest", "repository"].filter((k) => typeof p[k] !== "string" || !p[k]);
    if (missing.length > 0)
        return { ok: false, reason: `Deposit is missing ${missing.join(", ")}.` };
    if (typeof p.integrity_score !== "number" || !Number.isFinite(p.integrity_score)) {
        return { ok: false, reason: "Deposit has no integrity_score." };
    }
    if (p.integrity_score < 0 || p.integrity_score > 100) {
        return { ok: false, reason: "integrity_score is outside 0–100." };
    }
    if (typeof p.assertions !== "number" || p.assertions < 0) {
        return { ok: false, reason: "Deposit has no assertion count." };
    }
    const s = p.summary;
    if (!s ||
        typeof s !== "object" ||
        ["passed", "failed", "warned", "skipped"].some((k) => typeof s[k] !== "number")) {
        return { ok: false, reason: "Deposit has no complete summary." };
    }
    return { ok: true, payload: p };
}
/** Build the minimal proof the record is derived from. Hashes and counts only. */
function proofFrom(payload, claims) {
    return {
        schema_version: "0.1.0",
        issuer: "Proofwork",
        engine: "proofwork",
        created_at: new Date().toISOString(),
        ok: payload.verdict === "pass",
        repo: {
            // Not a filesystem path: nothing from the customer's runner is stored, and
            // a path would be the one field that leaked anything about their machine.
            root: payload.repository,
            is_git: true,
            branch: payload.branch ?? claims.ref ?? null,
            commit: payload.commit,
        },
        checks: [],
        summary: payload.summary,
        blockers: [],
        integrity_score: payload.integrity_score,
        binding: {
            algo: "sha256",
            commit: payload.commit,
            tree_digest: payload.tree_digest,
            file_count: 0,
            dirty: false,
            base_ref: null,
            base_ref_source: "none",
        },
    };
}
/**
 * Accept a deposit, or say exactly why not.
 *
 * The order is deliberate: authentication before authorisation before content.
 * A caller with a bad token learns nothing about whether their licence or their
 * payload would have been acceptable.
 */
export async function handleDeposit(req) {
    const audience = req.audience ?? DEPOSIT_AUDIENCE;
    const registryLogPath = req.registryLogPath;
    const depositLogPath = req.depositLogPath ?? DEPOSIT_LOG();
    /* 1 · Is this GitHub, and is it our workflow? */
    if (!req.oidcToken) {
        return { status: "rejected", code: 401, reason: "No GitHub OIDC token was presented." };
    }
    const oidc = await verifyGithubOidc({
        token: req.oidcToken,
        audience,
        ...(req.fetchJwks ? { fetchJwks: req.fetchJwks } : {}),
        ...(req.now !== undefined ? { now: req.now } : {}),
    });
    if (!oidc.ok)
        return { status: "rejected", code: 401, reason: oidc.reason };
    const claims = oidc.claims;
    const expected = req.expectedWorkflow ?? OFFICIAL_WORKFLOW;
    if (!isOfficialWorkflow(claims.job_workflow_ref, expected)) {
        // The single check that makes a remotely computed score signable. A run of
        // the customer's own workflow proves only that they can write YAML.
        return {
            status: "rejected",
            code: 403,
            reason: `Records are issued only for runs of ${expected}. This token reports ` +
                `${claims.job_workflow_ref ?? "no workflow"}, so the grading was not done by our code.`,
        };
    }
    /* 2 · Is there a paid licence, and is it this organisation's? */
    const licence = verifyLicense(req.licenceKey ?? "", req.publicKeyPem ?? undefined);
    if (!licence.valid || !licence.payload) {
        return { status: "rejected", code: 403, reason: `Licence rejected: ${licence.reason ?? "invalid"}` };
    }
    if (licence.tier === "free") {
        return {
            status: "rejected",
            code: 403,
            reason: "The free tier does not include signed records. Assured issues them.",
        };
    }
    /* 3 · Is the payload acceptable? */
    const parsed = parsePayload(req.body);
    if (!parsed.ok)
        return { status: "rejected", code: 400, reason: parsed.reason };
    const payload = parsed.payload;
    const licSubject = licence.payload.subject.trim().toLowerCase();
    if (payload.subject.trim().toLowerCase() !== licSubject) {
        // A certificate naming an organisation the licence was not issued to would
        // let one customer mint records for anybody.
        return {
            status: "rejected",
            code: 403,
            reason: `This licence is issued to "${licence.payload.subject}", and the deposit names ` +
                `"${payload.subject}". A record is issued to the licensed organisation.`,
        };
    }
    if (payload.verdict !== "pass") {
        // Denials are real and signed, but they are produced where the run happened
        // and belong to their holder. Minting one here from a self-reported verdict
        // would put a failure on our infrastructure that nobody asked us to record.
        return {
            status: "rejected",
            code: 400,
            reason: "Only a passing run is deposited. A failing run keeps its report locally.",
        };
    }
    /* 4 · Have we already issued for this exact run? */
    const key = idempotencyKey(licence.payload.jti, payload.repository, payload.commit);
    const prior = readDeposits(depositLogPath).find((d) => d.key === key);
    if (prior) {
        const existing = findEntry(registryLogPath, prior.record_id);
        if (existing)
            return { status: "already_issued", entry: existing, code: 200 };
    }
    /* 5 · Sign it. */
    const issue = req.issue ?? issueCredential;
    const proof = proofFrom(payload, claims);
    const issued = issue({
        proof,
        subject: licence.payload.subject,
        tier: licence.tier === "assured" ? "assured" : "certified",
        assertions: payload.assertions,
        score: payload.integrity_score,
        // Written to the issuer's own directory. `issueCredential` otherwise defaults
        // to `<proof.repo.root>/.proofwork`, and repo.root here is "owner/repo" —
        // which on this server is a relative path that would create a directory tree
        // inside the working directory.
        outDir: path.join(path.dirname(depositLogPath), "records"),
    });
    recordDeposit(depositLogPath, {
        key,
        record_id: issued.entry.record_id,
        repository: payload.repository,
        commit: payload.commit,
        at: new Date().toISOString(),
    });
    /* 6 · Tell the customer. Failure here must not undo the issuance. */
    if (req.onIssued) {
        try {
            await req.onIssued(issued.entry, claims);
        }
        catch {
            // The record is signed and in the log. A mail provider being down is not a
            // reason to fail a deposit the customer would then retry — and the retry
            // would return already_issued and send nothing either.
        }
    }
    return { status: "issued", entry: issued.entry, code: 201 };
}
function findEntry(registryLogPath, recordId) {
    try {
        const log = readLog(registryLogPath ??
            path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "registry.jsonl"));
        return log.find((e) => e.record_id === recordId) ?? null;
    }
    catch {
        return null;
    }
}
function recordDeposit(logPath, rec) {
    try {
        fs.mkdirSync(path.dirname(logPath), { recursive: true });
        fs.appendFileSync(logPath, `${JSON.stringify(rec)}\n`, "utf8");
    }
    catch {
        // Losing the note risks a duplicate on a re-run, which is better than
        // failing a deposit that has already been signed into the registry.
    }
}
