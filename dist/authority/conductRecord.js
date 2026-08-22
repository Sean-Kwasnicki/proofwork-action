/**
 * Authority packet — reconstructable agent conduct.
 *
 * The artefact a sandbox / market-surveillance officer files.
 * Not a certificate of lawfulness. CERTIFIED never means compliant.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { scoreProof } from "../scoring.js";
import { assertPublicClaims } from "../invariants/publicClaims.js";
import { LAW_CLOCK, inForceLabel } from "./lawClock.js";
import { issuerRegionFromEnv, isAuthorityFiling } from "./issuerRegion.js";
import { canonical } from "../license.js";
import { loadIssuerKeysIfPresent } from "../issuer.js";
import { proofDigest } from "../registry.js";
export const CONDUCT_SCHEMA = "proofwork.conduct.v1";
const CHECK_LAW = {
    "regulatory.disclosure": ["eu.ai-act.art50", "cen.pren18229-2"],
    "regulatory.record_keeping": ["eu.ai-act.art12", "cen.pren18229-1"],
    "regulatory.automated_decision": ["eu.gdpr.art22"],
    "agent_security.delegated_authority": ["eu.ai-act.art14", "cen.pren18229-3"],
    "agent_security.autonomy": ["eu.ai-act.art14", "cen.pren18229-3"],
    "integrity.workmanship": ["cen.en18286"],
    "integrity.verification": ["cen.en18286"],
    "integrity.change_test_bind": ["cen.en18286"],
};
const DISCLAIMER = "This record reconstructs what was observed in one commit. It is not a " +
    "determination of compliance, lawfulness, CE marking, or conformity under " +
    "the EU AI Act, GDPR, or the Cyber Resilience Act. A competent authority " +
    "draws that line. The word compliant does not apply to this document.";
function refsFor(checkId) {
    return (CHECK_LAW[checkId] ?? []).map((id) => {
        const r = LAW_CLOCK.find((x) => x.id === id);
        if (!r)
            return { id, label: id, force: "unmapped" };
        return { id: r.id, label: r.label, force: inForceLabel(r) };
    });
}
function runnerFromEnv(opts, env) {
    return {
        oidc_job_workflow_ref: opts.oidcJob ?? env.PROOFWORK_OIDC_JOB_WORKFLOW_REF ?? env.GITHUB_WORKFLOW_REF,
        action_digest: opts.actionDigest ?? env.PROOFWORK_ACTION_DIGEST,
    };
}
export function buildConductRecord(proof, opts = {}) {
    const env = opts.env ?? process.env;
    const score = scoreProof(proof);
    const band = score.band;
    const violations = assertPublicClaims({
        proofOk: proof.ok,
        earned: score.final,
        band,
        actionScore: score.final,
        depositScore: score.final,
    });
    const events = proof.checks
        .filter((c) => c.status !== "skip")
        .map((c) => ({
        id: c.id,
        status: c.status,
        observation: c.detail,
        refs: refsFor(c.id),
    }));
    const gaps = proof.checks
        .filter((c) => c.status === "skip")
        .map((c) => ({
        check_id: c.id,
        why: "skip",
        detail: c.detail,
    }));
    const loc = issuerRegionFromEnv(env);
    return {
        schema: CONDUCT_SCHEMA,
        created_at: proof.created_at,
        subject: opts.subject,
        tree: {
            commit: proof.repo.commit ?? proof.binding?.commit ?? null,
            tree_digest: proof.binding?.tree_digest ?? null,
            algo: proof.binding?.algo ?? null,
        },
        runner: runnerFromEnv(opts, env),
        issuer: {
            region: loc.region,
            jurisdiction: loc.jurisdiction,
            authority_filing: false,
        },
        proof_digest: proofDigest(proof),
        seal: null,
        integrity: {
            ok: proof.ok,
            earned: score.final,
            band,
            legal_conclusion: "none",
        },
        events,
        gaps,
        law_clock: LAW_CLOCK,
        claim_violations: violations,
        disclaimer: DISCLAIMER,
    };
}
export function renderConductPacket(record) {
    const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const rows = record.events
        .map((e) => `<tr><td>${esc(e.id)}</td><td>${esc(e.status)}</td><td>${esc(e.observation)}</td><td>${esc(e.refs.map((r) => `${r.label} (${r.force})`).join("; ") || "—")}</td></tr>`)
        .join("\n");
    const gaps = record.gaps
        .map((g) => `<li><code>${esc(g.check_id)}</code> — ${esc(g.detail)}</li>`)
        .join("\n");
    const clock = record.law_clock
        .map((l) => `<li>${esc(l.label)} — <b>${esc(inForceLabel(l))}</b>. ${esc(l.note)}</li>`)
        .join("\n");
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Proofwork conduct record</title>
<style>
  body { font: 15px/1.45 system-ui, sans-serif; max-width: 880px; margin: 32px auto; color: #111; }
  h1 { font-size: 22px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  td, th { border: 1px solid #ccc; padding: 6px 8px; vertical-align: top; }
  .ban { background: #111; color: #fff; padding: 12px 14px; }
  .note { color: #444; }
</style></head><body>
<p class="ban">Not a legal determination. Not CE. Not ISO. Not Article 40 presumption. Reconstructable conduct only.</p>
<h1>Agent conduct record</h1>
<p>${esc(record.disclaimer)}</p>
<p>Subject: ${esc(record.subject ?? "—")} · commit <code>${esc(record.tree.commit ?? "—")}</code> · tree <code>${esc(record.tree.tree_digest ?? "—")}</code></p>
<p>Integrity plane: <b>${esc(record.integrity.band)}</b> · ${record.integrity.earned}/100 · proof.ok=${String(record.integrity.ok)} · legal conclusion: none</p>
<p>Issuer region: <code>${esc(record.issuer.region)}</code> · jurisdiction <b>${esc(record.issuer.jurisdiction)}</b> · authority filing: ${record.issuer.authority_filing ? "yes" : "no"}</p>
<p>OIDC job: <code>${esc(record.runner.oidc_job_workflow_ref ?? "—")}</code> · Action digest: <code>${esc(record.runner.action_digest ?? "—")}</code></p>
<p>Seal: ${record.seal ? `ed25519 key ${esc(record.seal.key_id)} · hash ${esc(record.seal.payload_hash.slice(0, 16))}…` : "unsigned — not a filing"}</p>
<h2>Events (examined)</h2>
<table>
<tr><th>Check</th><th>Status</th><th>Observation in this tree</th><th>Refs (force)</th></tr>
${rows}
</table>
<h2>Gaps (skip = duty not engaged, never a pass)</h2>
<ul>${gaps || "<li>None</li>"}</ul>
<h2>Law clock on this date</h2>
<ul>${clock}</ul>
<p class="note">Print to PDF. Same numbers as the report card. Denied runs are included so a fail can be reconstructed.</p>
</body></html>`;
}
export function packetForbidsCompliant(html) {
    const lower = html.toLowerCase();
    if (!lower.includes("not a legal determination"))
        return false;
    if (/\bis compliant\b/.test(lower))
        return false;
    return true;
}
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
function unsignedBody(record) {
    const { seal: _seal, ...rest } = record;
    return canonical(rest);
}
export function sealConductRecord(record, keys) {
    const unsigned = {
        ...record,
        seal: null,
        issuer: {
            ...record.issuer,
            authority_filing: false,
        },
    };
    const payload_hash = sha256(unsignedBody(unsigned));
    const signature = crypto
        .sign(null, Buffer.from(payload_hash, "utf8"), crypto.createPrivateKey(keys.privateKeyPem))
        .toString("base64url");
    const filing = isAuthorityFiling(record.issuer.jurisdiction);
    return {
        ...unsigned,
        issuer: { ...record.issuer, authority_filing: filing },
        seal: { alg: "ed25519", key_id: keys.keyId, payload_hash, signature },
    };
}
export function verifyConductRecord(record, publicKeyPem) {
    const errors = [];
    if (record.schema !== CONDUCT_SCHEMA) {
        errors.push(`Unknown schema "${String(record.schema)}".`);
    }
    if (record.integrity?.legal_conclusion !== "none") {
        errors.push("legal_conclusion is not none — this packet overstates itself.");
    }
    if (/\bis compliant\b/i.test(JSON.stringify(record))) {
        errors.push("Packet contains the sentence 'is compliant'.");
    }
    if (!record.seal) {
        errors.push("Packet is not sealed. An official cannot file an unsigned record.");
        return {
            ok: false,
            sealed: false,
            authority_filing: false,
            errors,
            record,
            summary: `CONDUCT  NOT SEALED\n  ${errors.join("\n  ")}\n`,
        };
    }
    const unsigned = {
        ...record,
        seal: null,
        issuer: { ...record.issuer, authority_filing: false },
    };
    const recomputed = sha256(unsignedBody(unsigned));
    if (recomputed !== record.seal.payload_hash) {
        errors.push("Payload hash does not match — a field was altered after sealing.");
    }
    let sigOk = false;
    try {
        sigOk = crypto.verify(null, Buffer.from(record.seal.payload_hash, "utf8"), crypto.createPublicKey(publicKeyPem), Buffer.from(record.seal.signature, "base64url"));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk)
        errors.push("Issuer signature does not verify.");
    const sealed = errors.length === 0;
    const filing = sealed && isAuthorityFiling(record.issuer.jurisdiction) && record.issuer.authority_filing;
    if (sealed && !filing) {
        errors.push(`Sealed but not an authority filing (jurisdiction=${record.issuer.jurisdiction}, region=${record.issuer.region}). ` +
            "Set PROOFWORK_ISSUER_REGION to an EU region before sealing a packet an officer can file.");
    }
    const ok = sealed; // signature is the authenticity question; filing is a separate flag
    const summary = `CONDUCT  ${ok ? "AUTHENTIC" : "REJECTED"}\n` +
        `  Filing     ${filing ? "EU authority edition" : "not a filing"}\n` +
        `  Tree       ${record.tree.commit ?? "—"} / ${record.tree.tree_digest ?? "—"}\n` +
        `  Integrity  ${record.integrity.band} ${record.integrity.earned}/100 · legal conclusion: none\n` +
        (errors.length && !filing ? `  Note       ${errors[errors.length - 1]}\n` : "") +
        (ok ? "" : `  Errors     ${errors.join("; ")}\n`);
    return { ok, sealed, authority_filing: filing, errors: filing || !ok ? errors : errors, record, summary };
}
export function verifyConductFile(filePath, publicKeyPem) {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return verifyConductRecord(parsed, publicKeyPem);
}
export function writeConductArtifacts(dir, proof, opts = {}) {
    fs.mkdirSync(dir, { recursive: true });
    let rec = buildConductRecord(proof, opts);
    const keys = loadIssuerKeysIfPresent();
    if (keys) {
        rec = sealConductRecord(rec, keys);
    }
    const jsonPath = path.join(dir, "conduct.json");
    const htmlPath = path.join(dir, "conduct.html");
    fs.writeFileSync(jsonPath, `${JSON.stringify(rec, null, 2)}\n`, "utf8");
    fs.writeFileSync(htmlPath, renderConductPacket(rec), "utf8");
    return { jsonPath, htmlPath };
}
