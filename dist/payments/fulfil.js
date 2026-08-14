import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { purchaseFromEvent, renewalFromEvent, verifyWebhookSignature, } from "./checkout.js";
import { issueLicenseFor } from "../issuer.js";
/**
 * Turning a payment into a licence.
 *
 * ## The gap this closes
 *
 * Checkout sessions could be created, webhook signatures could be verified, and
 * purchases could be read out of an event — and none of it was joined up. A
 * reviewer walking the customer journey reached the paid tier by minting a
 * licence by hand and noted the obvious: *"this run used a local license mock,
 * not Stripe Checkout."*
 *
 * Every part existed. Nothing turned money into access, which is the one step
 * that makes the rest commercial rather than decorative.
 *
 * ## Idempotency is the whole problem
 *
 * Stripe retries a webhook until it receives a 2xx, and it will deliver the same
 * event more than once in normal operation — network timeouts, redeploys, a slow
 * handler. A fulfilment path that mints on every delivery hands one customer four
 * licences for one payment, and the duplicates are indistinguishable from real
 * ones because we signed them.
 *
 * So fulfilment records what it has already fulfilled, keyed by the Stripe
 * session id, and a repeat delivery returns the licence already issued rather
 * than making another. The ledger is written **before** the response is
 * considered successful: a crash between minting and recording would otherwise
 * reproduce exactly the bug the ledger exists to prevent.
 */
const FULFILMENT_LOG = () => process.env.PROOFWORK_FULFILMENT_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "fulfilments.jsonl");
export function readFulfilments(logPath = FULFILMENT_LOG()) {
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
 * One billing period, used only when Stripe did not tell us the real one.
 *
 * This was 365 days, which sold a year to everyone who paid for a month. The
 * site says "$99 / month" and "cancel anytime"; a licence that outlived the
 * period actually paid for made both of those untrue, and the customer would
 * have kept full access for eleven months they never bought.
 *
 * 31 days rather than 30: the fallback should never expire a licence *before*
 * the period somebody paid for, and months are 31 days at their longest. Erring
 * short would revoke access from a paying customer, which is the worse mistake
 * of the two.
 *
 * It is a fallback and nothing more. The real expiry is `current_period_end`
 * from Stripe, and every renewal replaces this with that.
 */
const FALLBACK_PERIOD_DAYS = 31;
/** Unix seconds to an ISO expiry, for a licence bound to a paid period. */
function expiryFromPeriodEnd(periodEnd) {
    if (periodEnd && Number.isFinite(periodEnd)) {
        return new Date(periodEnd * 1000).toISOString();
    }
    return new Date(Date.now() + FALLBACK_PERIOD_DAYS * 86_400_000).toISOString();
}
/**
 * Fulfil a Stripe webhook.
 *
 * Signature first, always. Reading fields off an unverified payload — even to
 * decide whether to ignore it — is how a webhook endpoint becomes a free licence
 * dispenser for anyone who can reach the URL.
 */
export function fulfilWebhook(input) {
    const sig = verifyWebhookSignature(input.payload, input.signatureHeader, input.webhookSecret, {
        ...(input.now !== undefined ? { now: input.now } : {}),
    });
    if (!sig.ok) {
        return { status: "rejected", reason: sig.reason ?? "Signature did not verify." };
    }
    let event;
    try {
        event = JSON.parse(input.payload);
    }
    catch {
        return { status: "rejected", reason: "Webhook body is not valid JSON." };
    }
    const purchase = purchaseFromEvent(event);
    if (purchase) {
        return fulfilPurchase({
            purchase,
            ...(input.logPath !== undefined ? { logPath: input.logPath } : {}),
            ...(input.issue !== undefined ? { issue: input.issue } : {}),
        });
    }
    /**
     * A renewal extends the licence to the next period.
     *
     * Checked after the checkout session, because the first billing cycle produces
     * both events. The session is the authoritative one for a first payment — it
     * carries the organisation and the email — and handling the invoice as well
     * would issue twice for one purchase. `renewLicence` refuses an organisation
     * with no prior fulfilment, which is what makes that ordering safe rather than
     * merely lucky.
     */
    const renewal = renewalFromEvent(event);
    if (renewal) {
        return renewLicence({
            renewal,
            ...(input.logPath !== undefined ? { logPath: input.logPath } : {}),
            ...(input.issue !== undefined ? { issue: input.issue } : {}),
        });
    }
    // Not an error. Stripe sends many event types — including the cancellation and
    // payment-failure ones — and a handler that 500s on the rest invites endless
    // retries and eventually gets the endpoint disabled.
    //
    // Cancellation needs no branch here on purpose: a licence expires at the end
    // of the period already paid for, and a cancelled subscription simply stops
    // producing invoices to extend it. Nothing has to be revoked, and the customer
    // keeps exactly the month they bought.
    return { status: "ignored", reason: "Not a completed checkout session or a paid invoice." };
}
/**
 * Issue a licence for a purchase, exactly once.
 *
 * Separated from the webhook so a licence can also be fulfilled manually — a
 * support case, a payment taken by invoice — through the same idempotent path
 * rather than a second one that drifts.
 */
export function fulfilPurchase(input) {
    const logPath = input.logPath ?? FULFILMENT_LOG();
    const issue = input.issue ?? issueLicenseFor;
    const { purchase } = input;
    const already = readFulfilments(logPath).find((f) => f.session_id === purchase.sessionId);
    if (already) {
        // Stripe retries until it gets a 2xx and re-delivers in normal operation.
        // Returning the existing licence is what stops one payment becoming four.
        return { status: "already_fulfilled", fulfilment: already };
    }
    // Expires when the paid period ends. `days` is still passed because the issuer
    // takes it, but `expiresAt` overrides it — and the fallback behind that is one
    // billing period, never a year.
    const expiresAt = expiryFromPeriodEnd(purchase.periodEnd);
    const issued = issue({
        subject: purchase.reference,
        tier: purchase.tier,
        days: FALLBACK_PERIOD_DAYS,
        expiresAt,
        repos: [],
        plan: `${purchase.tier} · ${(purchase.amountPaid / 100).toFixed(2)} USD / month`,
    });
    const fulfilment = {
        session_id: purchase.sessionId,
        reference: purchase.reference,
        email: purchase.email,
        subject: purchase.reference,
        tier: purchase.tier,
        amount_paid: purchase.amountPaid,
        license_key: issued.token,
        license_jti: issued.payload.jti,
        fulfilled_at: new Date().toISOString(),
        expires_at: expiresAt,
        ...(purchase.subscriptionId ? { subscription_id: purchase.subscriptionId } : {}),
        ...(purchase.customerId ? { customer_id: purchase.customerId } : {}),
        renewed_invoices: [],
    };
    // Recorded before the caller is told it succeeded. A crash after minting and
    // before writing would let the next delivery mint a second licence, which is
    // the failure this log exists to prevent.
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, `${JSON.stringify(fulfilment)}\n`, "utf8");
    return { status: "fulfilled", fulfilment };
}
/**
 * Extend an existing licence to the new paid period.
 *
 * ## Why this is an extension and not a new licence
 *
 * A renewal is the same customer continuing, so it re-issues the *same
 * organisation* a key running to the new period end. Minting a fresh unrelated
 * licence on every invoice would leave a customer holding twelve keys a year and
 * no way to tell which is current — and would make revocation useless, because
 * withdrawing one would leave eleven others working.
 *
 * ## Idempotent on the invoice
 *
 * Stripe redelivers invoices exactly as it redelivers any other event. Applying
 * the same one twice would push the expiry a month further each time, so one
 * renewal would silently buy three.
 *
 * ## What it refuses
 *
 * A renewal for an organisation with no prior fulfilment. That is either a
 * subscription created outside this flow or an attribution failure, and
 * extending the wrong organisation's licence is worse than extending none.
 */
export function renewLicence(input) {
    const logPath = input.logPath ?? FULFILMENT_LOG();
    const issue = input.issue ?? issueLicenseFor;
    const { renewal } = input;
    const rows = readFulfilments(logPath);
    // Match on the subscription where we have it, falling back to the
    // organisation. A subscription id is the stronger link; the organisation
    // covers a first fulfilment recorded before the id was known.
    const prior = [...rows]
        .reverse()
        .find((f) => (renewal.subscriptionId && f.subscription_id === renewal.subscriptionId) ||
        f.reference === renewal.reference);
    if (!prior) {
        return {
            status: "ignored",
            reason: `Invoice ${renewal.invoiceId} is for "${renewal.reference}", which has no prior ` +
                `fulfilment on this machine. Refusing to extend a licence that was never issued here.`,
        };
    }
    if (prior.renewed_invoices?.includes(renewal.invoiceId)) {
        return { status: "already_fulfilled", fulfilment: prior };
    }
    /**
     * The invoice that accompanies a first purchase is not a renewal.
     *
     * Stripe raises both `checkout.session.completed` and `invoice.paid` for the
     * first payment. The session is the authoritative one — it carries the
     * organisation and the email — and treating the invoice as a renewal as well
     * issued a *second* licence on day one, for the same period the customer had
     * just bought.
     *
     * Two independent signals, because each has a gap the other closes:
     *
     *   - `billing_reason: subscription_create` names the case exactly, and is
     *     absent from some payloads and from older API versions.
     *   - A period end that does not advance past the current expiry means there is
     *     nothing to extend, whatever the invoice claims to be. This holds even if
     *     Stripe changes its reason strings, and it also catches an out-of-order
     *     redelivery of an older invoice after a newer one has been applied.
     *
     * Either one is enough to skip. Requiring both would let a payload missing the
     * reason mint the duplicate this exists to prevent.
     */
    const currentExpiry = prior.expires_at ? Date.parse(prior.expires_at) : 0;
    const newExpiry = renewal.periodEnd * 1000;
    if (renewal.billingReason === "subscription_create") {
        return {
            status: "ignored",
            reason: `Invoice ${renewal.invoiceId} is the subscription-create invoice for ` +
                `"${renewal.reference}". The checkout session already issued that licence; ` +
                `extending here would hand them a second key for the month they just bought.`,
        };
    }
    if (Number.isFinite(currentExpiry) && newExpiry <= currentExpiry) {
        return {
            status: "ignored",
            reason: `Invoice ${renewal.invoiceId} covers a period ending ` +
                `${new Date(newExpiry).toISOString().slice(0, 10)}, which is not after the current ` +
                `expiry of ${prior.expires_at?.slice(0, 10)}. Nothing to extend.`,
        };
    }
    const expiresAt = expiryFromPeriodEnd(renewal.periodEnd);
    const issued = issue({
        subject: prior.reference,
        tier: prior.tier,
        days: FALLBACK_PERIOD_DAYS,
        expiresAt,
        repos: [],
        plan: `${prior.tier} · ${(renewal.amountPaid / 100).toFixed(2)} USD / month`,
    });
    const renewed = {
        ...prior,
        license_key: issued.token,
        license_jti: issued.payload.jti,
        fulfilled_at: new Date().toISOString(),
        expires_at: expiresAt,
        amount_paid: renewal.amountPaid,
        ...(renewal.subscriptionId ? { subscription_id: renewal.subscriptionId } : {}),
        ...(renewal.customerId ? { customer_id: renewal.customerId } : {}),
        renewed_invoices: [...(prior.renewed_invoices ?? []), renewal.invoiceId],
    };
    // Appended, not rewritten. The log is the record of what was sold, and an
    // earlier period having existed is a fact about the account.
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, `${JSON.stringify(renewed)}\n`, "utf8");
    return { status: "fulfilled", fulfilment: renewed };
}
/**
 * A webhook secret's fingerprint, for confirming the right one is configured
 * without printing it.
 */
export function webhookSecretFingerprint(secret) {
    return crypto.createHash("sha256").update(secret).digest("hex").slice(0, 12);
}
/** Rendered for an operator checking what has been sold and fulfilled. */
export function renderFulfilments(rows) {
    const rule = "─".repeat(74);
    if (rows.length === 0) {
        return [
            "",
            "  FULFILMENTS",
            `  ${rule}`,
            "",
            "  None. A licence is issued when Stripe reports a paid checkout session.",
            "",
            "  Point a webhook at your handler and call `fulfilWebhook`, or fulfil a",
            "  payment taken outside Stripe with `fulfilPurchase`.",
            "",
        ].join("\n");
    }
    const total = rows.reduce((s, r) => s + r.amount_paid, 0);
    return [
        "",
        "  FULFILMENTS",
        `  ${rule}`,
        "",
        ...rows
            .slice(-20)
            .map((r) => `  ${r.fulfilled_at.slice(0, 10)}  ${r.tier.padEnd(9)} ` +
            `$${(r.amount_paid / 100).toFixed(2).padStart(8)}  ${r.email.padEnd(30)} ${r.reference}`),
        "",
        `  ${rule}`,
        `  ${rows.length} licence(s) · $${(total / 100).toFixed(2)} collected`,
        "",
        "  Keyed by Stripe session id, so a re-delivered webhook returns the licence",
        "  already issued rather than minting another.",
        "",
    ].join("\n");
}
