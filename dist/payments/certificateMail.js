import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyLinkFor } from "../verifyHost.js";
import { mailConfig, resendSender } from "./licenceMail.js";
const CERT_DELIVERY_LOG = () => process.env.PROOFWORK_CERT_DELIVERY_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "certificate-deliveries.jsonl");
export function readCertificateDeliveries(logPath = CERT_DELIVERY_LOG()) {
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
function record(logPath, d) {
    try {
        fs.mkdirSync(path.dirname(logPath), { recursive: true });
        fs.appendFileSync(logPath, `${JSON.stringify(d)}\n`, "utf8");
    }
    catch {
        // The note is for us; the customer already has their certificate.
    }
}
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/**
 * The message.
 *
 * HTML with a plain-text alternative, because this one is meant to be forwarded
 * to a buyer or a reviewer and will be read in a mail client rather than a
 * terminal. Every interpolation is escaped: the subject line carries a
 * customer-supplied organization name, and this is the message most likely to be
 * shown to someone outside their company.
 */
export function renderCertificateEmail(entry, opts = {}) {
    const link = opts.verifyUrl ?? verifyLinkFor(entry.record_id).url;
    const commit = entry.commit ? entry.commit.slice(0, 8) : "";
    const bound = commit ? `commit ${commit}` : "the submitted bundle";
    const checkLine = link
        ? `Anyone can check it here:\n\n  ${link}\n\nor offline, with the record file and no network:\n\n  proofwork verify ${entry.record_id}.json`
        : `Anyone can check it offline, with the record file and no network:\n\n  proofwork verify ${entry.record_id}.json`;
    const text = [
        `Proofwork CERTIFIED — ${entry.subject}`,
        ``,
        `Record      ${entry.record_id}`,
        `Score       ${entry.integrity_score}/100`,
        `Bound to    ${bound}`,
        `Issued      ${entry.issued_at.slice(0, 10)}`,
        ``,
        checkLine,
        ``,
        `The certificate page is attached to this message. Open it and print to PDF`,
        `for a copy you can send on.`,
        ``,
        `What this attests: the code at ${bound} cleared the checks that applied to`,
        `it. It is not a security audit, not a correctness guarantee, and not a`,
        `certification under any statute. It describes one exact state — ship a`,
        `change and this record describes the previous version, which the CLI will`,
        `tell you.`,
        ``,
    ].join("\n");
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Proofwork certificate — ${esc(entry.subject)}</title></head>
<body style="margin:0;background:#f4f6f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif;color:#12201b">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f5;padding:28px 12px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border:1px solid #dde5e1;border-radius:12px;overflow:hidden">
        <tr><td style="background:#07100c;padding:22px 26px">
          <div style="font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#c9a961">Proofwork</div>
          <div style="font-size:20px;font-weight:600;color:#ffffff;margin-top:6px">Certified</div>
        </td></tr>
        <tr><td style="padding:26px">
          <p style="margin:0 0 18px;font-size:15px;line-height:1.6">
            <strong>${esc(entry.subject)}</strong> passed the Proofwork gate.
          </p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;font-size:14px;line-height:1.9;border-collapse:collapse">
            <tr><td style="color:#5c6f68;width:110px">Record</td><td style="font-family:ui-monospace,Menlo,monospace">${esc(entry.record_id)}</td></tr>
            <tr><td style="color:#5c6f68">Score</td><td><strong>${entry.integrity_score}/100</strong></td></tr>
            <tr><td style="color:#5c6f68">Bound to</td><td style="font-family:ui-monospace,Menlo,monospace">${esc(bound)}</td></tr>
            <tr><td style="color:#5c6f68">Issued</td><td>${esc(entry.issued_at.slice(0, 10))}</td></tr>
          </table>
          ${link
        ? `<p style="margin:22px 0 8px"><a href="${esc(link)}" style="display:inline-block;background:#12603a;color:#ffffff;text-decoration:none;padding:11px 18px;border-radius:8px;font-size:14px">Verify this record</a></p>
          <p style="margin:0 0 18px;font-size:12.5px;color:#5c6f68">Or offline, with the record file and no network: <code>proofwork verify ${esc(entry.record_id)}.json</code></p>`
        : `<p style="margin:22px 0 18px;font-size:13px;color:#5c6f68">Anyone can check it offline, with the record file and no network:<br><code>proofwork verify ${esc(entry.record_id)}.json</code></p>`}
          <p style="margin:0 0 16px;font-size:13px;color:#5c6f68">
            The certificate page is attached. Open it and print to PDF for a copy you can send on.
          </p>
          <p style="margin:0;font-size:12px;line-height:1.6;color:#7b8c86;border-top:1px solid #e6ecea;padding-top:14px">
            This attests that the code at ${esc(bound)} cleared the checks that applied to it. It is
            not a security audit, not a correctness guarantee, and not a certification under any
            statute. It describes one exact state — ship a change and it describes the previous
            version.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
    return { subject: `Proofwork CERTIFIED — ${entry.subject} (${entry.integrity_score}/100)`, text, html };
}
/**
 * Send the certificate for a passing record, once.
 *
 * Idempotent on `record_id` rather than on the run: re-issuing produces a new
 * record and a new message, while a retry of the same issuance sends nothing.
 */
export async function deliverCertificate(input) {
    const logPath = input.logPath ?? CERT_DELIVERY_LOG();
    const { entry } = input;
    const at = new Date().toISOString();
    if (entry.verdict !== "pass") {
        // Not an error. Denials are signed and recorded; they are simply not pushed
        // into an inbox, so a red CI run does not train anyone to filter our mail.
        return { status: "skipped", reason: "Not a passing record; certificates are emailed for passes only." };
    }
    const already = readCertificateDeliveries(logPath).find((d) => d.record_id === entry.record_id && d.status === "sent");
    if (already) {
        return { status: "skipped", reason: `Certificate for ${entry.record_id} was already sent.` };
    }
    const config = mailConfig();
    const send = input.send ?? (config ? resendSender(config.apiKey) : null);
    if (!send) {
        record(logPath, { record_id: entry.record_id, email: input.to, status: "skipped", at });
        return {
            status: "skipped",
            reason: "No mail provider configured (RESEND_API_KEY and PROOFWORK_MAIL_FROM). " +
                "The certificate was issued and written to disk; it has not been emailed.",
        };
    }
    if (!input.to) {
        record(logPath, { record_id: entry.record_id, email: "", status: "skipped", at });
        return { status: "skipped", reason: "No address to send to — sign in with `proofwork signup`." };
    }
    const { subject, text, html } = renderCertificateEmail(entry);
    const from = config?.from ?? "proofwork@test.invalid";
    const result = await send({ to: input.to, subject, text, html }, from);
    if (result.ok) {
        record(logPath, { record_id: entry.record_id, email: input.to, status: "sent", at });
        return { status: "sent" };
    }
    record(logPath, {
        record_id: entry.record_id,
        email: input.to,
        status: "failed",
        at,
        error: result.error,
    });
    return { status: "failed", error: result.error };
}
