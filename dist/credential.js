import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { appendRegistryEntry, readLog, verifyRegistryEntry, writeEntry, } from "./registry.js";
import { loadOrCreateIssuerKeys } from "./issuer.js";
import { issuerPublicKey } from "./license.js";
import { readRevocationList, revocationStatusFor } from "./revocation.js";
import { describeBinding } from "./bundle.js";
/**
 * Issuing and verifying a credential.
 *
 * ## The gap this closes
 *
 * The registry existed, was signed, and was tested — and nothing ever wrote to
 * it. A customer received a certificate document and a report card, both of which
 * they could have produced themselves by editing HTML, and no record existed that
 * anyone else could check.
 *
 * That inverted the entire proposition. What a customer buys is not a document
 * about their code; it is *a claim a third party will believe*. Documents are
 * copyable and editable. The signature is the product, and the signature was
 * never being applied.
 *
 * ## Where the issuer log lives
 *
 * On the issuer's machine, beside the private key, and never in the customer's
 * repository. A ledger the presenting party can rewrite answers "has this file
 * changed since I wrote it?" and cannot answer "did they actually pass?" — which
 * is the only question a buyer is asking.
 *
 * The customer receives their own entry as a file they can hand to anyone. It is
 * self-verifying: the recipient needs the record and the public key, nothing
 * else, and in particular no call to us. Verification that depended on our uptime
 * would make every customer's due-diligence conversation contingent on our
 * server being awake.
 */
const REGISTRY_LOG = () => process.env.PROOFWORK_REGISTRY_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "registry.jsonl");
/**
 * Sign a passing run into the registry and hand the customer their record.
 *
 * `issueCredential` remains pass-only: a *certificate* derives its value from
 * what it excludes, and a "certificate of denial" would be a contradiction that
 * screenshots badly. Failing runs are recorded by `issueDeniedRecord` below —
 * same signature, same log, different claim.
 */
export function issueCredential(opts) {
    if (!opts.proof.ok) {
        throw new Error("Refusing to issue a credential for a failing run.");
    }
    const keys = loadOrCreateIssuerKeys();
    const logPath = REGISTRY_LOG();
    const log = readLog(logPath);
    const entry = appendRegistryEntry(log, {
        // The graded score is substituted into the proof the record is built from, so
        // the signed figure and the printed figure are the same number by
        // construction rather than by two call sites agreeing.
        proof: { ...opts.proof, integrity_score: opts.score },
        subject: opts.subject,
        tier: opts.tier,
        privateKeyPem: keys.privateKeyPem,
        publicKeyPem: keys.publicKeyPem,
        assertions: opts.assertions,
    });
    writeEntry(logPath, entry);
    const outDir = opts.outDir ?? path.join(opts.proof.repo.root, ".proofwork");
    fs.mkdirSync(outDir, { recursive: true });
    const recordPath = path.join(outDir, `${entry.record_id}.json`);
    fs.writeFileSync(recordPath, `${JSON.stringify(entry, null, 2)}\n`, "utf8");
    return { entry, recordPath, logPath };
}
/**
 * Record a failing run.
 *
 * ## Why failures must be signed too
 *
 * Until now only passes were recorded, which made this a badge shop rather than
 * a control system. A buyer shown three certificates learns that three runs
 * passed; they learn nothing about the eleven that did not, because those left no
 * trace anywhere. An external reviewer named this precisely: *"buyers only see
 * trophies."*
 *
 * A denial record is the same artefact as a certificate — issuer-signed, bound to
 * one commit, independently verifiable — carrying the opposite claim. It is not a
 * punishment and it is not published by us. It goes to the holder, exactly like a
 * certificate does, and what makes it worth anything is that it **cannot be
 * quietly edited into a pass**.
 *
 * ## The limit, stated plainly
 *
 * This does not prevent someone running the gate privately and only showing you
 * their good days. Nothing local can: a customer who never runs the tool
 * generates no record at all, and no signature scheme fixes that.
 *
 * What it changes is the shape of the lie. Suppressing a denial now requires
 * withholding a record that has a sequence number in an issuer-side log, rather
 * than simply enjoying the fact that failures were never written down. A gap in a
 * sequence is a question a buyer can ask; an absence of evidence is not.
 */
export function issueDeniedRecord(opts) {
    if (opts.proof.ok) {
        throw new Error("Refusing to issue a denial record for a passing run.");
    }
    const keys = loadOrCreateIssuerKeys();
    const logPath = REGISTRY_LOG();
    const log = readLog(logPath);
    // `appendRegistryEntry` reads `proof.ok` to set the verdict, so a failing proof
    // produces `verdict: "fail"` without any special casing here. One code path
    // signs both outcomes, which is what keeps them equally hard to forge.
    const entry = appendRegistryEntry(log, {
        proof: { ...opts.proof, integrity_score: opts.score },
        subject: opts.subject,
        tier: opts.tier,
        privateKeyPem: keys.privateKeyPem,
        publicKeyPem: keys.publicKeyPem,
        assertions: opts.assertions,
    });
    writeEntry(logPath, entry);
    const outDir = opts.outDir ?? path.join(opts.proof.repo.root, ".proofwork");
    fs.mkdirSync(outDir, { recursive: true });
    const recordPath = path.join(outDir, `${entry.record_id}.json`);
    /**
     * The signed record is nested, not spread.
     *
     * The first version wrote `{ ...entry, reasons }`, which put an extra key
     * inside the object the signature covers. Verification recomputes the hash
     * over every field it finds, so the record failed to verify **the moment it
     * was issued** — a denial nobody could confirm was genuine, which is the one
     * thing it exists to be.
     *
     * Nesting keeps the signed bytes untouched and lets the file carry context
     * alongside. Anything added beside `record` is unsigned by construction, which
     * is the honest arrangement: the reasons are a convenience for the reader, and
     * only the record itself is evidence.
     */
    fs.writeFileSync(recordPath, `${JSON.stringify({ record: entry, reasons: opts.reasons.slice(0, 8) }, null, 2)}\n`, "utf8");
    return { entry, recordPath, logPath };
}
/**
 * Verify a record handed over by a customer.
 *
 * Deliberately takes a *file*, not a record id. A verifier that looked up an id
 * on our server would prove only that we have a row — and would fail whenever we
 * were down, in a customer's most important conversation. Verifying the artefact
 * itself needs nothing from us but the public key that is already compiled into
 * every copy of this tool.
 */
export function verifyCredentialFile(file, publicKeyPem) {
    const pub = publicKeyPem ?? issuerPublicKey();
    if (!pub) {
        return {
            ok: false,
            errors: ["This build carries no issuer key, so nothing can be verified against it."],
            summary: "Cannot verify — no issuer key in this build.",
        };
    }
    let entry;
    try {
        const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
        // Two shapes are accepted. A certificate record is the entry itself; a denial
        // record nests it under `record` so it can carry unsigned context alongside.
        // Verifying the nested object rather than its wrapper is what keeps the
        // signed bytes exactly as they were issued.
        entry = "record" in parsed && parsed.record ? parsed.record : parsed;
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return { ok: false, errors: [`Could not read a record from ${file}: ${msg}`], summary: "Not a readable record." };
    }
    const res = verifyRegistryEntry(entry, pub);
    /**
     * Revocation, checked against whatever list this machine holds.
     *
     * Kept separate from `verifyRegistryEntry` on purpose: "did we issue this?" must
     * stay answerable with nothing but the public key, or offline verification stops
     * being offline. This adds the second question — "do we still stand behind it?"
     * — and answers it when a list is available.
     *
     * A revoked record fails, whatever its signature says. An *unchecked* record
     * does not thereby pass; the summary states which question went unanswered, so
     * a reader is never left assuming a check ran that did not.
     */
    const revocation = revocationStatusFor(entry.record_id, readRevocationList(), pub);
    const errors = [...res.errors];
    if (revocation.revoked)
        errors.unshift(`Withdrawn by the issuer. ${revocation.note}`);
    const ok = res.ok && !revocation.revoked;
    return {
        ok,
        entry,
        errors,
        revocation,
        summary: renderVerification(entry, ok, errors, revocation),
    };
}
function renderVerification(entry, ok, errors, revocation) {
    const rule = "─".repeat(66);
    // Withdrawal gets its own heading. "VERIFICATION FAILED" is true but reads as
    // tampering or a corrupt file, when what happened is that we signed this record
    // and have since withdrawn it. Those call for different reactions from whoever
    // is holding it.
    if (revocation.revoked) {
        return [
            "",
            "  WITHDRAWN BY THE ISSUER",
            `  ${rule}`,
            "",
            `  Record     ${entry.record_id}`,
            `  Issued to  ${entry.subject}`,
            "",
            `  ${revocation.note}`,
            "",
            "  The signature is genuine — Proofwork did issue this record. It has since",
            "  been withdrawn and must not be relied on.",
            "",
        ].join("\n");
    }
    if (!ok) {
        return [
            "",
            "  VERIFICATION FAILED",
            `  ${rule}`,
            "",
            ...errors.map((e) => `  · ${e}`),
            "",
            "  Do not rely on this record.",
            "",
        ].join("\n");
    }
    const passed = entry.verdict === "pass";
    const isBundle = describeBinding(entry).kind === "bundle";
    const boundNoun = isBundle ? "bundle digest" : "commit";
    // Kept specific per binding. For a commit-bound record "a later commit may have
    // fixed the findings" is the exact statement; generalising it to cover bundles
    // would make the common case vaguer to accommodate the rarer one.
    const laterFix = isBundle
        ? "A later version may have fixed the findings"
        : "A later commit may have fixed the findings";
    // The signature check and the verdict are different questions, and the heading
    // answers the first. A denial record that verifies is a *genuine* record of a
    // failure — reporting that as "VERIFIED" alone would let a reader skim the
    // banner and conclude the opposite of what the record says.
    return [
        "",
        passed ? "  VERIFIED — CERTIFIED" : "  VERIFIED — DENIED",
        `  ${rule}`,
        "",
        `  Record     ${entry.record_id}`,
        `  Issued to  ${entry.subject}`,
        `  Verdict    ${passed ? "PASS" : "FAIL"} · ${entry.integrity_score}/100 · ${entry.tier}`,
        `  Assertions ${entry.assertions}`,
        `  ${describeBinding(entry).label.padEnd(10)} ${describeBinding(entry).value}`,
        `  Issued     ${entry.issued_at.slice(0, 10)}`,
        `  Expires    ${entry.expires_at.slice(0, 10)}`,
        "",
        `  This record was signed by Proofwork and has not been altered. The`,
        `  signature was checked locally — no call to Proofwork was made, and`,
        `  nothing here depends on trusting whoever handed you the file.`,
        "",
        // Stated either way. A reader who is not told the withdrawal check was
        // skipped will assume it ran, which is the assumption this line exists to
        // prevent.
        revocation.checked
            ? `  Withdrawal  ${revocation.note}`
            : `  Withdrawal  NOT CHECKED. ${revocation.note}`,
        "",
        // "the commit above" was printed even for bundle-bound records, where there
        // is no commit and the reader would go looking for one.
        // "the commit above" was printed even for bundle-bound records, where there is
        // no commit and the reader would go looking for one. The phrase stays on one
        // line so it reads as a single claim rather than wrapping mid-sentence.
        passed
            ? `  It attests that the code at the ${boundNoun} above cleared the checks that applied to it.\n` +
                `  It is not a statement that the software is safe, and it is not a\n` +
                `  conformity assessment under any statute.`
            : `  It attests that the code at the ${boundNoun} above did NOT clear the checks that applied to it.\n` +
                `  ${laterFix} — this record describes one exact state\n` +
                `  and makes no claim about any other.`,
        "",
    ].join("\n");
}
/** Every record we have issued. Issuer-side support lookup. */
export function issuedCredentials() {
    try {
        return readLog(REGISTRY_LOG());
    }
    catch {
        return [];
    }
}
