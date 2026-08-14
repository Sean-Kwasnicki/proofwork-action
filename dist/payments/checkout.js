import crypto from "node:crypto";
import { resolveStripe, stripeRequest } from "./stripe.js";
/**
 * Stripe product tax code.
 *
 * ## Why this is required rather than optional
 *
 * Stripe enables Managed Payments by default on new accounts, and it refuses any
 * line item without a tax code:
 *
 *     Invalid line_items[0]: the product tax code is missing.
 *
 * Without one, checkout fails for every account created after that default
 * landed — which is every account a new customer would open. It is not a
 * nice-to-have; the payment path does not function without it.
 *
 * ## What this value asserts
 *
 * `txcd_10103001` is Stripe's code for **Software as a Service (SaaS) — business
 * use**, which is what a subscription to this gate is: remotely hosted software
 * sold to a business, with no transfer of a copy and no professional service
 * attached.
 *
 * That is a tax classification and it drives how tax is calculated in every
 * jurisdiction Stripe collects for. It is set here so the choice is visible in
 * version control and reviewable rather than buried in dashboard state, and it is
 * overridable for an operator whose accountant reaches a different conclusion —
 * that call belongs to them, not to this file.
 */
export const PRODUCT_TAX_CODE = process.env.PROOFWORK_TAX_CODE ?? "txcd_10103001";
/**
 * Prices are declared here rather than read from Stripe.
 *
 * A price that lives only in the dashboard can be changed without a commit, which
 * means the amount charged and the amount in version control can silently
 * diverge. Declaring it here makes a price change a reviewable event — and lets
 * the checkout path verify that what Stripe is about to charge matches what this
 * repository says it should.
 */
export const PRICES = {
    /**
     * The one plan sold self-serve. $99/mo, matching the site.
     *
     * It was 29900 here while the site advertised $99 — a customer clicking the
     * button would have been charged three times the price they were shown. Caught
     * by putting a real session through the live test-mode API and reading the
     * amount back from Stripe rather than trusting the constant.
     *
     * `siteClaims.test.ts` now compares this figure against the page, so the two
     * cannot drift apart again silently.
     */
    assured: {
        tier: "assured",
        amount: 9900,
        currency: "usd",
        name: "Proofwork Assured",
        description: "The graded report card with every finding by file and line, remediation for each one, a " +
            "certificate bound to one commit or bundle digest, and a registry record a third party can " +
            "verify without trusting you.",
    },
    /**
     * Not sold self-serve.
     *
     * `certified` remains a valid licence tier — records and licences carry it, and
     * issued ones must keep working — but there is no Certified plan on the site,
     * so nothing should be creating a Checkout session for it. Priced identically
     * rather than left at a figure nobody is offered.
     */
    certified: {
        tier: "certified",
        amount: 9900,
        currency: "usd",
        name: "Proofwork Certified",
        description: "Full audit, the graded report card, remediation for every finding, a certificate bound to " +
            "one commit, and a registry record a third party can verify without trusting you.",
    },
};
/**
 * Create a hosted Checkout session.
 *
 * Creating a session does not charge anybody — it produces a link. The guarantee
 * that one payment yields one licence is enforced at fulfilment, keyed on the
 * session id. See the note on `idempotencyKey` below.
 */
export async function createCheckoutSession(input) {
    const price = PRICES[input.tier];
    const config = input.config ?? resolveStripe();
    if (config.mode === "live") {
        // Not a refusal — live mode is reachable deliberately — but it is recorded
        // where an operator will see it, because a real charge should never be the
        // quiet outcome of running a command.
        console.error(`[proofwork] LIVE Stripe session: ${price.name}, ${price.amount / 100} ${price.currency.toUpperCase()} — this will charge a real card.`);
    }
    /**
     * No derived idempotency key here, and that is deliberate.
     *
     * ## What it was protecting against, and why that was the wrong worry
     *
     * The key was derived from buyer, tier, and amount so an impatient double-click
     * could not create "a second session and a second charge". But creating a
     * Checkout Session does not charge anyone — it creates a link. Money moves when
     * the customer completes payment, and they can only complete one. Two sessions
     * is untidy; it is not a double charge.
     *
     * ## What it cost
     *
     * Stripe caches the response for an idempotency key — **including the error** —
     * for 24 hours. A first attempt that failed for any reason therefore poisoned
     * that buyer's key for a day: same buyer, same tier, same amount produced the
     * same key, and Stripe replayed the stale failure rather than retrying.
     *
     * That is not hypothetical. It happened on this account: a create failed
     * because Managed Payments needed a tax code, and after that was fixed the
     * wrapper kept returning the original error while a byte-identical raw request
     * succeeded. A paying customer would have been unable to buy for 24 hours
     * because of one transient failure, with nothing to tell them why.
     *
     * ## Where the guarantee actually lives
     *
     * One payment produces one licence, enforced at fulfilment and keyed on the
     * Stripe session id — see `fulfilPurchase`. Stripe redelivers webhooks in
     * normal operation, so that is where duplicate protection has to be, and it is
     * unaffected by anything here.
     *
     * A caller who genuinely needs one can pass `idempotencyKey`.
     */
    const idempotencyKey = input.idempotencyKey;
    const res = await stripeRequest("/v1/checkout/sessions", {
        method: "POST",
        config,
        idempotencyKey,
        params: {
            /**
             * A subscription, not a one-off payment.
             *
             * The page says "$99 / month" and "cancel anytime". A `payment` session
             * charges once and never again, so every one of those customers would
             * have paid one month and kept a licence that outlived it — the site
             * describing a subscription while the code sold a perpetual key.
             *
             * `subscription` also gives the webhook a `current_period_end` to expire
             * the licence against, and an `invoice.paid` on each renewal to extend
             * it. Both are what make "cancel anytime" mean something.
             */
            mode: "subscription",
            success_url: input.successUrl,
            cancel_url: input.cancelUrl,
            customer_email: input.email,
            client_reference_id: input.reference,
            // Carried onto the subscription so a renewal invoice can be traced back
            // to the organisation without a second API call.
            subscription_data: { metadata: { tier: input.tier, reference: input.reference } },
            line_items: [
                {
                    quantity: 1,
                    price_data: {
                        currency: price.currency,
                        unit_amount: price.amount,
                        // Monthly. The interval is what makes this a subscription price
                        // rather than a one-off amount that happens to repeat.
                        recurring: { interval: "month" },
                        product_data: {
                            name: price.name,
                            description: price.description,
                            // Required by Managed Payments, which Stripe enables by default.
                            // See PRODUCT_TAX_CODE — this is a tax classification, not a
                            // formatting detail.
                            tax_code: PRODUCT_TAX_CODE,
                        },
                    },
                },
            ],
            metadata: { tier: input.tier, reference: input.reference },
        },
    });
    if (!res.ok || !res.data) {
        return { ok: false, error: res.error?.message ?? "Stripe did not return a session." };
    }
    // Verify Stripe agrees with our price book. A mismatch means something changed
    // outside version control, and charging an amount this repository does not
    // declare is not something to discover from a customer's statement.
    if (res.data.amount_total !== undefined && res.data.amount_total !== price.amount) {
        return {
            ok: false,
            error: `Stripe was going to charge ${res.data.amount_total} but this build declares ${price.amount}. ` +
                `Refusing to proceed — the price in the dashboard and the price in version control disagree.`,
        };
    }
    return {
        ok: true,
        session: {
            id: res.data.id,
            url: res.data.url,
            amount: price.amount,
            currency: price.currency,
            tier: input.tier,
            clientReferenceId: input.reference,
        },
    };
}
/**
 * Put one real payment on the dashboard, in test mode.
 *
 * Every weaker signal has already been ruled out by `stripeStatus`: a key can be
 * present, well-formed, and authenticate against `/v1/balance` while the account
 * still cannot take a payment. The only thing that settles "are we actually
 * connected" is a payment appearing where the operator can see it.
 *
 * Test mode is not a simulation of this — it *is* this, against a ledger that
 * holds no real money. The charge is genuine, the record is genuine, and nothing
 * leaves anyone's bank.
 *
 * Live mode is refused outright, with no opt-in. Everywhere else in this module
 * live is reachable deliberately because a real product eventually has to take
 * real money; here it never needs to, because the entire purpose is verification.
 * A diagnostic that can spend real money is not a diagnostic.
 */
export async function runTestCharge(input) {
    const config = input.config ?? resolveStripe();
    if (config.mode === "live") {
        return {
            ok: false,
            error: "Refusing to run a test charge against a LIVE key. This command exists to prove the " +
                "connection works, and it must never be able to move real money to do that. Use a test " +
                "key (sk_test_…).",
        };
    }
    if (config.mode === "unconfigured") {
        return { ok: false, error: config.reason };
    }
    if (input.amountCents < 50) {
        // Stripe's own minimum for USD. Failing here with a clear reason beats a
        // confusing API error about an amount that is too small.
        return { ok: false, error: "Stripe's minimum charge is 50 cents. Use --amount 500 for $5.00." };
    }
    const res = await stripeRequest("/v1/payment_intents", {
        method: "POST",
        config,
        // Derived from the amount, so re-running this command does not litter the
        // dashboard with duplicates while someone is debugging.
        idempotencyKey: `proofwork-testcharge-${input.amountCents}-${input.currency ?? "usd"}`,
        params: {
            amount: input.amountCents,
            currency: input.currency ?? "usd",
            // Stripe's canonical test card token. No card details are handled here,
            // which is the point — this file never sees a real card and never should.
            payment_method: "pm_card_visa",
            confirm: true,
            description: input.description ?? "Proofwork connectivity test",
            automatic_payment_methods: { enabled: true, allow_redirects: "never" },
            metadata: { source: "proofwork", purpose: "connectivity_test" },
        },
    });
    if (!res.ok || !res.data) {
        return { ok: false, error: res.error?.message ?? "Stripe did not return a payment intent." };
    }
    return {
        ok: res.data.status === "succeeded",
        id: res.data.id,
        amount: res.data.amount,
        currency: res.data.currency,
        status: res.data.status,
        livemode: res.data.livemode,
        ...(res.data.status !== "succeeded"
            ? { error: `Payment reached status "${res.data.status}" rather than "succeeded".` }
            : {}),
    };
}
/** Rendered so the operator knows exactly what to look for on the dashboard. */
export function renderTestCharge(r, mode) {
    const money = r.amount !== undefined ? `$${(r.amount / 100).toFixed(2)} ${(r.currency ?? "usd").toUpperCase()}` : "—";
    if (!r.ok) {
        return [
            "",
            "  TEST CHARGE — FAILED",
            `  ${"─".repeat(66)}`,
            "",
            `  ${r.error ?? "Unknown failure."}`,
            "",
            "  Nothing was charged.",
            "",
        ].join("\n");
    }
    return [
        "",
        "  TEST CHARGE — SUCCEEDED",
        `  ${"─".repeat(66)}`,
        "",
        `  Amount     ${money}`,
        `  Status     ${r.status}`,
        `  Payment id ${r.id}`,
        `  Livemode   ${r.livemode ? "TRUE — REAL MONEY MOVED" : "false — test data, no real money"}`,
        `  Mode       ${mode}`,
        "",
        "  Check it here:",
        "",
        `    https://dashboard.stripe.com/test/payments/${r.id}`,
        "",
        "  Make sure the dashboard is in TEST mode — the toggle is top-right. Test",
        "  payments do not appear in the live view, and that is the correct behaviour,",
        "  not a sign that something failed.",
        "",
        "  Your real balance is unchanged. Test-mode payments settle against a ledger",
        "  that holds no money.",
        "",
    ].join("\n");
}
/* ─────────────────────────────────────────── webhook verification ─── */
/**
 * Verify a Stripe webhook signature.
 *
 * Without this, the endpoint that grants licences accepts a licence grant from
 * anybody who can reach the URL. It is the single most consequential function in
 * the payment path and the one most often skipped, because a webhook "works" in
 * testing whether or not the signature is checked.
 *
 * Implemented against Stripe's scheme directly rather than pulled from a
 * package, and compared in constant time — a naive `===` on an HMAC leaks the
 * correct value a byte at a time to anyone willing to measure.
 */
export function verifyWebhookSignature(payload, signatureHeader, secret, opts = {}) {
    const tolerance = opts.toleranceSeconds ?? 300;
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    const parts = Object.fromEntries(signatureHeader
        .split(",")
        .map((p) => p.trim().split("="))
        .filter((p) => p.length === 2));
    const timestamp = Number(parts.t);
    if (!Number.isFinite(timestamp))
        return { ok: false, reason: "Signature header has no timestamp." };
    // A replayed event is a valid signature on stale data. Without a freshness
    // window, a captured "payment succeeded" can be resubmitted indefinitely.
    if (Math.abs(now - timestamp) > tolerance) {
        return { ok: false, reason: `Signature timestamp is outside the ${tolerance}s tolerance.` };
    }
    const expected = crypto
        .createHmac("sha256", secret)
        .update(`${timestamp}.${payload}`, "utf8")
        .digest("hex");
    const provided = parts.v1;
    if (!provided)
        return { ok: false, reason: "Signature header has no v1 signature." };
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(provided, "hex");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return { ok: false, reason: "Signature does not match — this request was not sent by Stripe." };
    }
    return { ok: true };
}
/**
 * Read a completed purchase out of a verified webhook event.
 *
 * Returns null for anything that is not a completed, paid checkout. Treating an
 * unpaid or incomplete session as a purchase would issue licences for money that
 * never arrived, and `checkout.session.completed` fires before payment settles
 * for some methods — so payment_status is checked rather than assumed.
 */
export function purchaseFromEvent(event) {
    const e = event;
    if (e.type !== "checkout.session.completed")
        return null;
    const o = e.data?.object;
    if (!o)
        return null;
    if (o.payment_status !== "paid")
        return null;
    const tier = o.metadata?.tier;
    if (tier !== "certified" && tier !== "assured")
        return null;
    const reference = o.client_reference_id;
    const email = o.customer_email ?? o.customer_details?.email;
    if (!reference || !email || !o.id)
        return null;
    // `subscription` arrives as an id, or as the expanded object when the caller
    // asked Stripe to expand it. Both shapes are read rather than assuming one,
    // because which one turns up depends on how the event was fetched.
    const sub = o.subscription;
    const subscriptionId = typeof sub === "string" ? sub : sub?.id;
    const periodEnd = typeof sub === "object" ? sub?.current_period_end : undefined;
    return {
        reference,
        tier,
        email,
        amountPaid: o.amount_total ?? 0,
        sessionId: o.id,
        ...(subscriptionId ? { subscriptionId } : {}),
        ...(o.customer ? { customerId: o.customer } : {}),
        ...(periodEnd ? { periodEnd } : {}),
    };
}
export function renewalFromEvent(event) {
    const e = event;
    if (e.type !== "invoice.paid")
        return null;
    const o = e.data?.object;
    if (!o?.id)
        return null;
    // An invoice that is not paid extends nothing. Stripe sends `invoice.paid`
    // only on success, but the status is checked rather than inferred from the
    // event name — the two have disagreed before in other people's postmortems.
    if (o.status && o.status !== "paid")
        return null;
    const sub = o.subscription;
    const subscriptionId = typeof sub === "string" ? sub : sub?.id;
    if (!subscriptionId)
        return null;
    const reference = o.subscription_details?.metadata?.reference ?? o.lines?.data?.[0]?.metadata?.reference;
    if (!reference)
        return null;
    const periodEnd = o.lines?.data?.[0]?.period?.end;
    if (!periodEnd)
        return null;
    return {
        invoiceId: o.id,
        reference,
        subscriptionId,
        ...(o.customer ? { customerId: o.customer } : {}),
        periodEnd,
        amountPaid: o.amount_paid ?? 0,
        ...(o.billing_reason ? { billingReason: o.billing_reason } : {}),
    };
}
