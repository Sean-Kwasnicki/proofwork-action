import fs from "node:fs";
import path from "node:path";
import { describeBinding } from "./bundle.js";
import { verifyHost, verifyLinkFor } from "./verifyHost.js";
/**
 * The badge — the part that travels.
 *
 * A certificate is read once, by a buyer, during due diligence. A badge is seen
 * repeatedly, by people who were not looking for it: on a README, a pricing page,
 * a LinkedIn profile. It is the only artefact here that does marketing work, and
 * it is the reason a customer tells someone else we exist.
 *
 * Three forms, because they are consumed differently:
 *
 *   SVG        for a README or a site footer. Scales, stays sharp, no request
 *              to a third party — a badge that phones home would leak every
 *              visitor of every customer's page back to us.
 *   Social     1200×630, for LinkedIn and Open Graph. Rendered as HTML the
 *              customer screenshots or prints, so there is no image pipeline.
 *   Markdown   the snippet they paste. Most people will never open the others.
 *
 * ## The rule the badge has to obey
 *
 * It states a verdict and a record id, and nothing else. Every claim on it must
 * be checkable against the signed record — a badge that says more than the
 * credential behind it is a badge we cannot defend, and defending it is the whole
 * business.
 */
const GREEN = "#3ef58f";
const INK = "#070a09";
const GREY = "#9db3ab";
const GOLD = "#c9a961";
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/**
 * Inline SVG badge.
 *
 * Self-contained on purpose: no external font, no remote image, no script. A
 * README badge that fetched anything would be a tracking pixel on every
 * customer's repository, and no amount of convenience justifies that.
 */
export function badgeSvg(entry) {
    const label = entry.verdict === "pass" ? "VERIFIED" : "NOT VERIFIED";
    const accent = entry.verdict === "pass" ? GREEN : "#e0554f";
    const score = `${entry.integrity_score}/100`;
    // Monospace advances are predictable enough to size the plate without measuring.
    const idWidth = entry.record_id.length * 6.2;
    const width = Math.round(214 + idWidth);
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="28" viewBox="0 0 ${width} 28" role="img" aria-label="Proofwork ${esc(label)} — ${esc(score)} — record ${esc(entry.record_id)}">
  <title>Proofwork ${esc(label)} · ${esc(score)} · ${esc(entry.record_id)}</title>
  <rect width="${width}" height="28" rx="4" fill="${INK}"/>
  <rect x="0" y="0" width="3" height="28" fill="${accent}"/>
  <text x="14" y="18.5" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="11" font-weight="700" fill="${GOLD}" letter-spacing="1.4">PROOFWORK</text>
  <text x="104" y="18.5" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="11" font-weight="700" fill="${accent}" letter-spacing="0.8">${esc(label)}</text>
  <text x="${104 + label.length * 7.6 + 12}" y="18.5" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" font-size="10.5" fill="${GREY}">${esc(score)} · ${esc(entry.record_id)}</text>
</svg>
`;
}
/** README snippet. The form most customers will actually use. */
export function badgeMarkdown(entry, verifyUrl) {
    const alt = `Proofwork ${entry.verdict === "pass" ? "Verified" : "Not Verified"} — ${entry.integrity_score}/100`;
    // A hardcoded host produces a dead link the day before the service exists and
    // the day after it moves. A 404 on a verification link is worse than no link:
    // it invites the reader to conclude the certificate is fake.
    const link = verifyLinkFor(entry.record_id);
    const url = verifyUrl ?? link.url;
    return url
        ? `[![${alt}](./proofwork-badge.svg)](${url})`
        : `![${alt}](./proofwork-badge.svg)

<!-- No verify host configured. Anyone can check this
     record offline with: proofwork verify ${entry.record_id}.json -->`;
}
/**
 * 1200×630 social card, as a printable page.
 *
 * HTML rather than a generated PNG so there is no image toolchain to install and
 * nothing to keep in sync with the certificate's styling. The customer prints to
 * PDF or screenshots at that ratio; both give LinkedIn what it wants.
 */
export function socialCardHtml(entry, opts = {}) {
    const pass = entry.verdict === "pass";
    const accent = pass ? GREEN : "#e0554f";
    const verdict = pass ? "CERTIFIED" : "NOT CERTIFIED";
    return `<!doctype html>
<meta charset="utf-8">
<title>Proofwork credential — ${esc(entry.subject)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  /* 1200x630 is LinkedIn's card ratio. Fixed so a screenshot or a print is the
     right shape without the customer having to crop anything. */
  @page { size: 1200px 630px; margin: 0 }
  *{box-sizing:border-box}
  html,body{margin:0;background:${INK};color:#eef5f2;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif}
  .card{width:1200px;height:630px;position:relative;overflow:hidden;
    background:radial-gradient(120% 80% at 50% 0%, rgba(62,245,143,.10) 0%, transparent 58%),
               linear-gradient(#0b100e,#070a09);
    display:flex;flex-direction:column;justify-content:center;padding:0 96px}
  .card::before{content:"";position:absolute;inset:0 auto 0 0;width:6px;background:${accent}}
  .mark{font-family:ui-monospace,Menlo,monospace;font-size:15px;letter-spacing:.34em;
    color:${GOLD};text-transform:uppercase}
  h1{font-size:64px;line-height:1.06;margin:26px 0 0;font-weight:700;letter-spacing:-.02em}
  .sub{font-family:ui-monospace,Menlo,monospace;font-size:19px;color:${GREEN};margin-top:14px}
  .row{display:flex;gap:64px;margin-top:52px;padding-top:34px;border-top:1px solid rgba(255,255,255,.10)}
  .cell .k{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:.22em;
    text-transform:uppercase;color:${GREY}}
  .cell .v{font-size:38px;font-weight:700;margin-top:8px}
  .cell .v.good{color:${accent}}
  .foot{position:absolute;left:96px;bottom:38px;right:96px;display:flex;
    justify-content:space-between;font-family:ui-monospace,Menlo,monospace;
    font-size:13px;color:${GREY}}
  @media print { .card{page-break-after:avoid} }
</style>
<div class="card">
  <div class="mark">Proofwork · Independent Verification</div>
  <h1>${esc(entry.subject)}</h1>
  <div class="sub">${esc(opts.repository ?? "")}${opts.repository ? " · " : ""}${esc(describeBinding(entry).short)}</div>
  <div class="row">
    <div class="cell"><div class="k">Verdict</div><div class="v good">${esc(verdict)}</div></div>
    <div class="cell"><div class="k">Integrity</div><div class="v">${entry.integrity_score}<span style="font-size:19px;color:${GREY}">/100</span></div></div>
    <div class="cell"><div class="k">Assertions cleared</div><div class="v">${entry.assertions}</div></div>
  </div>
  <div class="foot">
    <span>Record ${esc(entry.record_id)}</span>
    <span>${esc(verifyLinkFor(entry.record_id).configured ? "Verify at " + (verifyHost() ?? "") + " — no account required" : "proofwork verify " + entry.record_id + ".json — no account required")}</span>
  </div>
</div>
`;
}
/**
 * Write every badge form beside the certificate.
 *
 * All three at once because a customer who has to run a second command for the
 * social card will not run it, and the social card is the one that travels.
 */
export function writeBadges(outDir, entry, opts = {}) {
    fs.mkdirSync(outDir, { recursive: true });
    const svgPath = path.join(outDir, "proofwork-badge.svg");
    const socialPath = path.join(outDir, "proofwork-badge-social.html");
    const mdPath = path.join(outDir, "proofwork-badge.md");
    fs.writeFileSync(svgPath, badgeSvg(entry), "utf8");
    fs.writeFileSync(socialPath, socialCardHtml(entry, opts), "utf8");
    fs.writeFileSync(mdPath, [
        "# Your Proofwork badge",
        "",
        "## README / site footer",
        "",
        "```markdown",
        badgeMarkdown(entry, opts.verifyUrl),
        "```",
        "",
        "## LinkedIn / social",
        "",
        "Open `proofwork-badge-social.html` and print to PDF, or screenshot it.",
        "It is already sized 1200×630, which is what LinkedIn expects.",
        "",
        "## What this badge claims",
        "",
        `Record **${entry.record_id}** — ${entry.verdict.toUpperCase()}, ${entry.integrity_score}/100,`,
        `${entry.assertions} assertions, at ${describeBinding(entry).phrase}.`,
        "",
        "Every figure on the badge is in the signed record. Anyone can check it with",
        "`proofwork verify` and the record file — no account, and no call to Proofwork.",
        "",
        `It attests that the code at ${describeBinding(entry).phrase} cleared the checks that applied to it.`,
        "It is not a statement that the software is safe.",
        "",
    ].join("\n"), "utf8");
    return { svg: svgPath, social: socialPath, markdown: mdPath };
}
