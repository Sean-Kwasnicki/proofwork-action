import {
  APPROVAL_THRESHOLD_CENTS,
  DAILY_SPEND_CEILING_CENTS,
  requireServiceKey,
} from "./config.js";
import { appendAudit, sumChargesToday } from "./audit.js";
import { receiptEmail } from "./mail.js";

/** Stripe-shaped client injected for tests / runtime. */
export async function chargeInvoice(client, input, opts = {}) {
  const key = requireServiceKey(opts.env);
  const amountCents = Number(input.amountCents);
  if (!Number.isFinite(amountCents) || amountCents <= 0) {
    throw new Error("amountCents must be a positive number");
  }

  if (amountCents > APPROVAL_THRESHOLD_CENTS) {
    const queued = appendAudit(
      {
        type: "charge",
        status: "awaiting_human",
        invoiceId: input.invoiceId,
        amountCents,
        reason: "above_approval_threshold",
      },
      opts.logPath,
    );
    return { ok: false, status: "awaiting_human", audit: queued };
  }

  const spent = sumChargesToday(opts.logPath);
  if (spent + amountCents > DAILY_SPEND_CEILING_CENTS) {
    const blocked = appendAudit(
      {
        type: "charge",
        status: "blocked_ceiling",
        invoiceId: input.invoiceId,
        amountCents,
        spentTodayCents: spent,
        ceilingCents: DAILY_SPEND_CEILING_CENTS,
      },
      opts.logPath,
    );
    return { ok: false, status: "blocked_ceiling", audit: blocked };
  }

  const payment = await client.createCharge({
    apiKey: key,
    amountCents,
    currency: input.currency || "usd",
    idempotencyKey: `billing-sync:${input.invoiceId}`,
  });

  const audit = appendAudit(
    {
      type: "charge",
      status: "succeeded",
      invoiceId: input.invoiceId,
      amountCents,
      paymentId: payment.id,
    },
    opts.logPath,
  );

  const email = receiptEmail({
    to: input.customerEmail,
    invoiceId: input.invoiceId,
    amountCents,
  });

  return { ok: true, status: "succeeded", payment, audit, email };
}
