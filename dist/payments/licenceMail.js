import fs from "node:fs";
import os from "node:os";
import path from "node:path";
/**
 * Read the mail configuration, or explain what is missing.
 *
 * Both halves are required. An API key without a from-address cannot send, and a
 * from-address on a domain nobody has verified is rejected at the provider —
 * `onrender.com` in particular cannot send mail.
 */
export function mailConfig() {
    const apiKey = (process.env.RESEND_API_KEY ?? "").trim();
    const from = (process.env.PROOFWORK_MAIL_FROM ??
        process.env.RESEND_FROM ??
        "").trim();
    if (!apiKey || !from)
        return null;
    return { apiKey, from };
}
export const mailConfigured = () => mailConfig() !== null;
/* --------------------------------------------------------- the provider --- */
/**
 * Resend, over `fetch`.
 *
 * No SDK: this project ships with no runtime dependencies, and a mail client is
 * one POST. Adding a package to the box that holds the signing key, to save
 * fifteen lines, is a poor trade.
 *
 * The response body is read on failure because "Resend said no" without the
 * reason is unactionable — an unverified domain and an invalid key look the same
 * from the outside. The request body is never echoed, because it contains the
 * licence.
 */
export function resendSender(apiKey) {
    return async (msg, from) => {
        try {
            const res = await fetch("https://api.resend.com/emails", {
                method: "POST",
                headers: {
                    authorization: `Bearer ${apiKey}`,
                    "content-type": "application/json",
                },
                body: JSON.stringify({
                    from,
                    to: [msg.to],
                    subject: msg.subject,
                    text: msg.text,
                    ...(msg.html ? { html: msg.html } : {}),
                }),
                // Bounded so a slow provider cannot hold the webhook open until Stripe
                // gives up and retries a payment that was already fulfilled.
                signal: AbortSignal.timeout(10_000),
            });
            if (res.ok)
                return { ok: true };
            const detail = await res.text().catch(() => "");
            return { ok: false, error: `Resend returned HTTP ${res.status}: ${detail.slice(0, 300)}` };
        }
        catch (e) {
            return { ok: false, error: e instanceof Error ? e.message : String(e) };
        }
    };
}
/* ------------------------------------------------------------ the email --- */
const escapeHtml = (s) => s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
export function renderLicenceEmail(f) {
    const expires = f.expires_at ? f.expires_at.slice(0, 10) : "the end of the paid period";
    const plan = f.tier === "assured" ? "Assured" : "Certified";
    const org = f.reference;
    const email = f.email;
    const key = f.license_key;
    const activateHint = `${f.license_key.slice(0, 12)}...`;
    const subject = `Your Proofwork ${plan} licence is ready — ${org}`;
    const text = [
        `Proofwork`,
        ``,
        `Your ${plan} licence is ready`,
        ``,
        `Thank you for your payment. This message is your licence for ${org}.`,
        `Stripe has sent a separate receipt for the charge. That receipt is the`,
        `record of payment. It does not include this key, because the key is`,
        `created only after payment is confirmed.`,
        ``,
        `Organisation     ${org}`,
        `Plan             Proofwork ${plan}  ·  $99 / month`,
        `Valid through    ${expires}`,
        ``,
        `Licence key`,
        `${key}`,
        ``,
        `Treat this key as a password. Anyone who has it can use Proofwork ${plan}`,
        `as ${org}. If it is exposed, contact us. We will withdraw it and issue`,
        `a replacement.`,
        ``,
        `Getting started`,
        ``,
        `1. Sign in with the organisation name you entered at checkout`,
        `   proofwork signup --email ${email} --org "${org}"`,
        ``,
        `2. Activate the licence on your machine`,
        `   proofwork activate ${activateHint}`,
        ``,
        `3. Confirm the paid tier is active`,
        `   proofwork whoami`,
        ``,
        `For CI, store the key as a repository secret:`,
        `   PROOFWORK_LICENSE=<paste the key above>`,
        ``,
        `If whoami still says free, the organisation name does not match this`,
        `licence. Sign in as "${org}", or ask us to reissue it against the name`,
        `you want. We will not apply one organisation's licence to another.`,
        ``,
        `Questions — reply to this email, or to your Stripe receipt, and include`,
        `the organisation name.`,
        ``,
        `— The Proofwork team`,
        `https://agent-proofwork.onrender.com/`,
        ``,
    ].join("\n");
    const o = escapeHtml(org);
    const e = escapeHtml(email);
    const k = escapeHtml(key);
    const x = escapeHtml(expires);
    const p = escapeHtml(plan);
    const a = escapeHtml(activateHint);
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#14201c;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f6f5;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellspacing="0" cellpadding="0" style="max-width:560px;width:100%;background:#ffffff;border:1px solid #e3e8e6;border-radius:12px;overflow:hidden;">
        <tr>
          <td style="padding:28px 36px 20px;border-bottom:1px solid #eef2f0;">
            <div style="font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#1a9a5c;font-weight:700;">Proofwork</div>
            <h1 style="margin:10px 0 0;font-size:22px;line-height:1.25;font-weight:650;color:#0d1614;">Your ${p} licence is ready</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 36px 8px;font-size:15px;line-height:1.55;color:#3a4a46;">
            Thank you for your payment. This message is the licence for <strong style="color:#14201c;">${o}</strong>.
            Stripe has sent a separate receipt for the charge. That receipt is the record of payment and does not include this key.
          </td>
        </tr>
        <tr>
          <td style="padding:16px 36px 8px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f7faf8;border:1px solid #e3e8e6;border-radius:8px;">
              <tr><td style="padding:14px 18px;font-size:13px;color:#5d706e;">Organisation</td><td style="padding:14px 18px;font-size:13px;color:#14201c;text-align:right;font-weight:600;">${o}</td></tr>
              <tr><td style="padding:0 18px 14px;font-size:13px;color:#5d706e;">Plan</td><td style="padding:0 18px 14px;font-size:13px;color:#14201c;text-align:right;font-weight:600;">Proofwork ${p} · $99 / month</td></tr>
              <tr><td style="padding:0 18px 14px;font-size:13px;color:#5d706e;">Valid through</td><td style="padding:0 18px 14px;font-size:13px;color:#14201c;text-align:right;font-weight:600;">${x}</td></tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 36px 8px;font-size:13px;font-weight:600;color:#14201c;">Licence key</td>
        </tr>
        <tr>
          <td style="padding:0 36px 8px;">
            <div style="background:#0d1614;color:#d7f5e6;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;padding:14px 16px;border-radius:8px;word-break:break-all;">${k}</div>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 36px 20px;font-size:12px;line-height:1.5;color:#5d706e;">
            Treat this key as a password. Anyone who has it can use Proofwork ${p} as ${o}. If it is exposed, contact us and we will withdraw it and issue a replacement.
          </td>
        </tr>
        <tr>
          <td style="padding:0 36px 24px;">
            <div style="font-size:13px;font-weight:600;color:#14201c;margin-bottom:10px;">Getting started</div>
            <ol style="margin:0;padding-left:18px;color:#3a4a46;font-size:14px;line-height:1.55;">
              <li style="margin-bottom:10px;">Sign in with the organisation name you entered at checkout.<br>
                <code style="display:block;margin-top:6px;background:#f7faf8;border:1px solid #e3e8e6;border-radius:6px;padding:8px 10px;font-size:12px;color:#14201c;">proofwork signup --email ${e} --org "${o}"</code>
              </li>
              <li style="margin-bottom:10px;">Activate the licence on your machine.<br>
                <code style="display:block;margin-top:6px;background:#f7faf8;border:1px solid #e3e8e6;border-radius:6px;padding:8px 10px;font-size:12px;color:#14201c;">proofwork activate ${a}</code>
              </li>
              <li style="margin-bottom:10px;">Confirm the paid tier is active.<br>
                <code style="display:block;margin-top:6px;background:#f7faf8;border:1px solid #e3e8e6;border-radius:6px;padding:8px 10px;font-size:12px;color:#14201c;">proofwork whoami</code>
              </li>
            </ol>
            <p style="margin:14px 0 0;font-size:13px;color:#3a4a46;">For CI, add a repository secret named <code>PROOFWORK_LICENSE</code> with the key above.</p>
            <p style="margin:12px 0 0;font-size:13px;color:#3a4a46;">If <code>whoami</code> still says free, the organisation name does not match this licence. Sign in as “${o}”, or ask us to reissue it against the name you want.</p>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 36px 28px;border-top:1px solid #eef2f0;font-size:12px;line-height:1.5;color:#5d706e;">
            Questions — reply to this email, or to your Stripe receipt, and include the organisation name.<br><br>
            — The Proofwork team<br>
            <a href="https://agent-proofwork.onrender.com/" style="color:#1a9a5c;">agent-proofwork.onrender.com</a>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
    return { subject, text, html };
}
const DELIVERY_LOG = () => process.env.PROOFWORK_DELIVERY_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "deliveries.jsonl");
export function readDeliveries(logPath = DELIVERY_LOG()) {
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
        // The record is for us; the customer already has their key. Losing the note
        // must not turn a delivered licence into a failed webhook.
    }
}
/**
 * Which paid customers are still owed their key.
 *
 * Counted rather than assumed. Without this, a provider outage looks exactly
 * like a quiet week — the licences are minted, the money is in, and nobody finds
 * out until a customer asks where their key is.
 */
export function undelivered(fulfilments, deliveries = readDeliveries()) {
    const sent = new Set(deliveries.filter((d) => d.status === "sent").map((d) => d.session_id));
    return fulfilments.filter((f) => !sent.has(f.session_id));
}
/**
 * Email one freshly minted licence.
 *
 * Call only on a first `fulfilled`. Never on `already_fulfilled` — that is a
 * re-delivery of a webhook we have already answered, and sending again would
 * mail the key a second time for one payment.
 */
export async function deliverLicence(input) {
    const logPath = input.logPath ?? DELIVERY_LOG();
    const { fulfilment } = input;
    const at = new Date().toISOString();
    const config = mailConfig();
    // An injected sender stands in for the configuration, so tests exercise the
    // real path without a key and without reaching the network.
    const send = input.send ?? (config ? resendSender(config.apiKey) : null);
    if (!send) {
        record(logPath, {
            session_id: fulfilment.session_id,
            email: fulfilment.email,
            status: "skipped",
            at,
        });
        return {
            status: "skipped",
            reason: "No mail provider configured (RESEND_API_KEY and PROOFWORK_MAIL_FROM). " +
                "The licence was minted and recorded; it has to be delivered by hand.",
        };
    }
    if (!fulfilment.email) {
        record(logPath, { session_id: fulfilment.session_id, email: "", status: "skipped", at });
        return { status: "skipped", reason: "The checkout session carried no email address to send to." };
    }
    const from = config?.from ?? "proofwork@test.invalid";
    const { subject, text, html } = renderLicenceEmail(fulfilment);
    const result = await send({ to: fulfilment.email, subject, text, html }, from);
    if (result.ok) {
        record(logPath, { session_id: fulfilment.session_id, email: fulfilment.email, status: "sent", at });
        return { status: "sent" };
    }
    record(logPath, {
        session_id: fulfilment.session_id,
        email: fulfilment.email,
        status: "failed",
        at,
        error: result.error,
    });
    return { status: "failed", error: result.error };
}
