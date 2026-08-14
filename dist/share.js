import fs from "node:fs";
import path from "node:path";
import { runCertify } from "./certify.js";
import { runProof } from "./run.js";
import { proofToAgentBrief } from "./report.js";
/** Copy-paste block agents and humans put on PRs — the social object of the product. */
export function proofToShareCard(proof, cert) {
    const tier = cert?.tier === "certified" ? "CERTIFIED" : proof.ok ? "CLEARED" : "DENIED";
    const seal = cert?.seal ? ` · seal \`${cert.seal}\`` : "";
    const score = typeof proof.integrity_score === "number" ? `${proof.integrity_score}/100` : "n/a";
    const lines = [
        `### Proofwork ${tier}`,
        "",
        proof.ok
            ? `Independent merge gate: **PASS** (integrity ${score})${seal}`
            : `Independent merge gate: **FAIL** (integrity ${score}) — do not merge on agent narration alone.`,
        "",
        "```",
        proofToAgentBrief(proof),
        "```",
        "",
        proof.ok
            ? "_Issuer: Proofwork — not the coding agent under test._"
            : "_Fix blockers, re-run `proofwork status` / `proofwork certify`, then update this card._",
    ];
    return `${lines.join("\n")}\n`;
}
export function runShare(root) {
    const proof = runProof({ root, fast: true, strict: true });
    const cert = runCertify({ root, maxCapacity: true });
    const card = proofToShareCard(proof, cert);
    const outPath = path.join(root, ".proofwork", "SHARE.md");
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, card, "utf8");
    return { card, outPath, ok: cert.tier === "certified" };
}
