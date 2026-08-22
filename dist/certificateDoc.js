import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { buildReportCard } from "./reportCard.js";
import { describeBinding } from "./bundle.js";
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/**
 * A stable, human-checkable id for this document.
 *
 * Derived from the proof rather than random, so re-issuing the same verified
 * state produces the same id. A certificate whose id changed on every render
 * would be impossible to reference in a contract or a security review.
 */
export function certificateId(proof) {
    const basis = JSON.stringify({
        commit: proof.repo.commit,
        tree: proof.binding?.tree_digest ?? null,
        ok: proof.ok,
        score: proof.integrity_score,
        checks: proof.checks.map((c) => [c.id, c.status]),
    });
    return `pwc_${crypto.createHash("sha256").update(basis).digest("hex").slice(0, 16)}`;
}
/** Lines describing what was examined — outcomes only, never rule names. */
function verifiedLines(card) {
    return card.categories
        .filter((c) => c.status !== "not_assessed")
        .map((c) => {
        const mark = c.status === "clear" ? "&#10022;" : "&#9702;";
        const qualifier = c.status === "clear"
            ? ""
            : ` <em style="color:var(--grey-2)">(${c.earned}/${c.possible} — see report card)</em>`;
        return `        <div class="vrow"><span class="tick">${mark}</span><span><b>${esc(c.name)}</b> &mdash; ${esc(c.means)}${qualifier}</span></div>`;
    })
        .join("\n");
}
function notAssessedNote(card) {
    if (card.not_assessed.length === 0)
        return "";
    return `
      <p class="note">
        Not assessed, because these duties did not apply to this system:
        ${esc(card.not_assessed.join(", "))}. They are excluded from the grade rather than
        assumed to pass.
      </p>`;
}
export function renderCertificateHtml(input) {
    const { proof, subject, assertions } = input;
    if (!proof.ok) {
        throw new Error("Refusing to render a certificate for a run that did not pass. A denied run gets a report " +
            "card; there is no certificate of failure, and a downgraded-looking one could be cropped " +
            "into something that reads as a pass.");
    }
    const card = buildReportCard(proof, subject);
    const id = certificateId(proof);
    // What this certificate is bound to, named by what it is. A bundle-bound proof
    // printed "commit unbound" here, which told the reader to look for a git commit
    // that does not exist.
    const bound = describeBinding(proof.binding ?? { commit: proof.repo.commit });
    const tree = bound.kind === "bundle" ? null : proof.binding?.tree_digest?.slice(0, 16) ?? null;
    const repo = input.repository ?? proof.repo.root;
    const issued = new Date().toISOString().slice(0, 10);
    const families = proof.checks.length;
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proofwork — Certificate ${esc(id)}</title>
<style>
  :root{
    --ink:#070a09;--ink-2:#0d1211;--edge:#22302b;--edge-2:#2f4038;
    --gold:#c9a961;--gold-soft:rgba(201,169,97,.08);--green:#3ef58f;--green-soft:rgba(62,245,143,.09);
    --white:#f4f8f6;--grey:#93a8a2;--grey-2:#61756f;
    --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
    --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  /* The background sits on html as well as body. With it on body alone, any
     viewport taller than the document — or an overscroll — shows the browser's
     default white behind a document that is otherwise entirely dark. It reads as
     a rendering fault on the one artefact a customer forwards to their buyer. */
  html{overflow-x:clip;background:var(--ink)}
  body{margin:0;background:var(--ink);color:var(--white);font-family:var(--sans);
    line-height:1.62;padding:40px 20px;overflow-x:clip;min-height:100vh}
  .page{max-width:min(880px,100%);margin:0 auto}
  .cert{position:relative;border:1px solid var(--edge-2);border-radius:6px;
    background:radial-gradient(120% 80% at 50% 0%, var(--green-soft) 0%, transparent 55%),
               linear-gradient(var(--ink-2), #080c0b);
    box-shadow:0 30px 80px -40px #000, 0 0 0 1px var(--gold-soft)}
  .cert-inner{margin:14px;border:1px solid rgba(201,169,97,.34);border-radius:3px;
    padding:44px 44px 36px;position:relative}
  .cert-inner::before{content:"";position:absolute;inset:6px;
    border:1px solid rgba(201,169,97,.13);border-radius:2px;pointer-events:none}
  .crest{text-align:center;margin-bottom:24px}
  .wordmark{font-family:var(--mono);font-size:.8rem;letter-spacing:.44em;
    text-transform:uppercase;color:var(--gold);text-indent:.44em}
  .orn{display:flex;align-items:center;justify-content:center;gap:12px;margin:14px auto 0;max-width:280px}
  .orn i{flex:1;height:1px;background:linear-gradient(90deg,transparent,rgba(201,169,97,.55),transparent)}
  .orn b{color:var(--gold);font-size:.62rem;letter-spacing:.3em}
  h1{text-align:center;font-family:var(--serif);font-size:clamp(1.5rem,4.1vw,2.3rem);
    letter-spacing:.008em;line-height:1.16;margin:0;font-weight:600}
  .sub{text-align:center;font-family:var(--mono);font-size:.66rem;letter-spacing:.22em;
    text-transform:uppercase;color:var(--grey-2);margin-top:12px}
  .awarded{text-align:center;margin-top:32px}
  .awarded .label{font-family:var(--mono);font-size:.63rem;letter-spacing:.24em;
    text-transform:uppercase;color:var(--grey-2)}
  .awarded .subject{font-family:var(--serif);font-size:clamp(1.65rem,4.8vw,2.5rem);
    color:var(--white);margin:12px 0 6px;line-height:1.1;letter-spacing:-.012em}
  .awarded .repo{font-family:var(--mono);font-size:.77rem;color:var(--green);word-break:break-all}
  .statement{max-width:54ch;margin:26px auto 0;text-align:center;color:var(--grey);
    font-size:.95rem;line-height:1.68}
  .statement em{color:var(--white);font-style:normal}
  .verdict{display:flex;justify-content:center;margin:30px auto 0;flex-wrap:wrap;
    border-top:1px solid rgba(201,169,97,.2);border-bottom:1px solid rgba(201,169,97,.2)}
  .vcell{flex:1 1 150px;text-align:center;padding:19px 14px;border-left:1px solid rgba(201,169,97,.12)}
  .vcell:first-child{border-left:none}
  .vcell .k{font-family:var(--mono);font-size:.59rem;letter-spacing:.2em;
    text-transform:uppercase;color:var(--grey-2)}
  .vcell .v{font-family:var(--serif);font-size:1.85rem;line-height:1.1;margin-top:7px;color:var(--white)}
  .vcell .v.good{color:var(--green)}
  .hdr{font-family:var(--mono);font-size:.61rem;letter-spacing:.22em;text-transform:uppercase;
    color:var(--grey-2);text-align:center;margin-bottom:15px}
  .verified{margin:28px auto 0;max-width:620px}
  .vrow{display:flex;gap:11px;align-items:flex-start;padding:7px 0;font-size:.88rem;color:var(--grey)}
  .vrow b{color:var(--white);font-weight:600}
  .tick{color:var(--gold);flex-shrink:0}
  .note{text-align:center;font-size:.75rem;color:var(--grey-2);max-width:52ch;
    margin:14px auto 0;line-height:1.6;font-style:italic}
  .foot{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;
    margin-top:36px;flex-wrap:wrap}
  .sig{flex:1 1 220px}
  .sig .line{border-bottom:1px solid rgba(201,169,97,.4);height:26px}
  .sig .who{font-family:var(--mono);font-size:.61rem;letter-spacing:.14em;
    text-transform:uppercase;color:var(--grey-2);margin-top:8px}
  .idblock{margin-top:24px;padding-top:18px;border-top:1px solid rgba(201,169,97,.16);
    font-family:var(--mono);font-size:.62rem;color:var(--grey-2);line-height:1.9;
    word-break:break-all;text-align:center}
  .idblock b{color:var(--grey)}
  .limits{max-width:640px;margin:26px auto 0;font-size:.72rem;color:var(--grey-2);
    line-height:1.7;text-align:center}
  @media (max-width:600px){.cert-inner{padding:28px 20px 24px;margin:9px}}
</style>
</head>
<body>
<div class="page">
  <div class="cert">
    <div class="cert-inner">

      <div class="crest">
        <div class="wordmark">Proofwork</div>
        <div class="orn"><i></i><b>&#9670;</b><i></i></div>
      </div>

      <h1>Certificate of Verified<br>Build Integrity</h1>
      <div class="sub">Independent verification &middot; Issued by Proofwork</div>

      <div class="awarded">
        <div class="label">Awarded to</div>
        <div class="subject">${esc(subject)}</div>
        <div class="repo">${esc(repo)} &middot; ${esc(bound.label)} ${esc(bound.short)}</div>
      </div>

      <p class="statement">
        This certifies that the work identified below was independently examined by Proofwork on
        ${issued}, and that <em>no blocking finding was recorded against any duty that applied to
        it</em>.
      </p>

      <div class="verdict">
        <div class="vcell">
          <div class="k">Verdict</div>
          <!-- The band already carries the 85 rule; the colour has to follow it,
               or a provisional certificate is printed in the certified green. -->
          <div class="v${card.overall.band === "certified" ? " good" : ""}">${esc(card.overall.band.toUpperCase())}</div>
        </div>
        <div class="vcell">
          <div class="k">Grade</div>
          <div class="v">${esc(card.overall.grade)}<span style="font-size:1rem;color:var(--grey-2)"> &middot; ${card.overall.earned}/100</span></div>
        </div>
        <div class="vcell">
          <div class="k">Assertions cleared</div>
          <div class="v">${assertions}</div>
        </div>
      </div>

      <p class="note">
        ${assertions} independent conditions across ${families} verification families &mdash; every one an
        automated test with a defined pass and fail, not a reviewer's impression.
      </p>

      <div class="verified">
        <div class="hdr">Examined and found sound</div>
${verifiedLines(card)}
      </div>
${notAssessedNote(card)}

      <p class="limits">
        <b style="color:var(--grey)">Said carefully.</b> This attests to what was examined in the
        code identified above, at ${esc(bound.phrase)}. It is not a statement that the
        software is safe, that its operator is compliant with any law, and it is not a conformity
        assessment under any statute. Proofwork is not an auditor and not a certification body.
        What this document provides is evidence; the determination remains with whoever is asking.
        Legal conclusion: none. The word compliant does not apply to this certificate.
      </p>

      <div class="foot">
        <div class="sig">
          <div class="line"></div>
          <div class="who">Issued by Proofwork &middot; automated</div>
        </div>
        <div class="sig">
          <div class="line"></div>
          <div class="who">Verified against ${esc(bound.phrase)}</div>
        </div>
      </div>

      <div class="idblock">
        <b>Certificate</b> ${esc(id)}<br>
        ${input.recordId ? `<b>Registry record</b> ${esc(input.recordId)}<br>` : ""}
        ${bound.kind === "bundle"
        ? `<b>Bundle SHA-256</b> ${esc(bound.value.slice(0, 32))}&hellip;<br>`
        : tree
            ? `<b>Tree digest</b> ${esc(tree)}&hellip;<br>`
            : ""}
        <b>Issued</b> ${issued}
      </div>

    </div>
  </div>
</div>
</body>
</html>
`;
}
/**
 * Write the certificate. Returns the path written.
 *
 * `outDir` is where the operator wants the artefact, which is not necessarily
 * inside the repository being graded — and by default should not be. Grading
 * somebody else's code and leaving files in their working tree is a side effect
 * nobody asked for; the caller now decides, and defaults to its own directory.
 *
 * The `root` fallback is kept for callers that genuinely mean "next to the
 * proof", such as a team running the gate on their own repository in CI.
 */
export function writeCertificateDoc(root, input, outDir) {
    const html = renderCertificateHtml(input);
    const dir = outDir ?? path.join(root, ".proofwork");
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "certificate.html");
    fs.writeFileSync(file, html, "utf8");
    return file;
}
