import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { runAccept } from "./accept.js";
import { appendAttestation } from "./attestation.js";
import { proofToAgentBrief } from "./report.js";
import { runProof } from "./run.js";
function sealOf(parts) {
    const body = JSON.stringify(parts);
    return crypto.createHash("sha256").update(body).digest("hex").slice(0, 16);
}
function badgeSvg(cert) {
    const pass = cert.ok && cert.tier === "certified";
    const cleared = cert.ok && cert.tier === "cleared";
    const fill = pass ? "#1f6b4a" : cleared ? "#b45309" : "#7f1d1d";
    const title = pass ? "CERTIFIED" : cleared ? "CLEARED" : "DENIED";
    const sub = pass
        ? "Max-capacity integrity"
        : cleared
            ? "Integrity gate passed"
            : "Not certified";
    return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="320" height="96" viewBox="0 0 320 96" role="img" aria-label="Proofwork ${title}">
  <rect width="320" height="96" rx="0" fill="#101820"/>
  <rect x="0" y="0" width="8" height="96" fill="${fill}"/>
  <text x="24" y="36" fill="#e8eef2" font-family="ui-monospace, monospace" font-size="18" font-weight="700">PROOFWORK ${title}</text>
  <text x="24" y="58" fill="#9aa8b5" font-family="ui-monospace, monospace" font-size="12">${sub} · score ${cert.integrity_score}</text>
  <text x="24" y="78" fill="#6b7a88" font-family="ui-monospace, monospace" font-size="10">seal ${cert.seal}</text>
</svg>
`;
}
/**
 * Certify a repo/agent surface after the max-capacity gate.
 * CERTIFIED = accept PASS + Proof PASS + integrity_score 100 (strict bar).
 * CLEARED = accept PASS + Proof PASS but score < 100 (warns allowed only if failOnWarn off — rare).
 * DENIED = anything else — no vanity badge.
 */
export function runCertify(opts) {
    const root = opts.root;
    const maxCapacity = opts.maxCapacity !== false;
    const accept = runAccept(root);
    const proof = runProof({ root, fast: true, strict: true });
    const score = proof.integrity_score ?? 0;
    const reasons = [];
    if (!accept.ok)
        reasons.push("accept gate failed — install/scaffold incomplete");
    if (!proof.ok)
        reasons.push(`proof failed: ${proof.blockers.slice(0, 2).join("; ") || "see doctor"}`);
    if (maxCapacity && proof.ok && accept.ok && score < 100) {
        reasons.push(`integrity_score ${score} < 100 — max-capacity CERTIFIED requires a clean score`);
    }
    let tier = "none";
    let label = "DENIED — not certified";
    if (accept.ok && proof.ok && score >= 100) {
        tier = "certified";
        label = "CERTIFIED — max-capacity integrity";
    }
    else if (accept.ok && proof.ok && !maxCapacity) {
        tier = "cleared";
        label = "CLEARED — integrity gate passed";
    }
    const ok = tier === "certified" || tier === "cleared";
    const seal = sealOf({
        tier,
        score,
        proof_ok: proof.ok,
        accept_ok: accept.ok,
        created_day: new Date().toISOString().slice(0, 10),
        root: path.basename(root),
        blockers: proof.blockers,
    });
    const outDir = path.join(root, ".proofwork");
    fs.mkdirSync(outDir, { recursive: true });
    const certificate_json_path = path.join(outDir, "CERTIFICATE.json");
    const badge_svg_path = path.join(outDir, "badge.svg");
    const cert = {
        schema_version: "0.1.0",
        product: "Proofwork",
        tier,
        ok,
        label,
        created_at: new Date().toISOString(),
        root,
        integrity_score: score,
        proof_ok: proof.ok,
        accept_ok: accept.ok,
        seal,
        reasons,
        badge_svg_path,
        certificate_json_path,
    };
    fs.writeFileSync(certificate_json_path, `${JSON.stringify(cert, null, 2)}\n`, "utf8");
    fs.writeFileSync(badge_svg_path, badgeSvg(cert), "utf8");
    // Tamper-evident local chain (not a public blockchain)
    try {
        appendAttestation(root, proof, cert, proofToAgentBrief(proof));
    }
    catch {
        // attestation must not break certify I/O; verify command will surface issues
    }
    return cert;
}
