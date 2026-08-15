import { IDENTITY } from "./config.js";

export function receiptEmail({ to, invoiceId, amountCents }) {
  const dollars = (amountCents / 100).toFixed(2);
  return {
    from: IDENTITY.mailbox,
    to,
    subject: `Receipt for invoice ${invoiceId}`,
    body: [
      `Hello,`,
      ``,
      `This message is from an AI billing agent (${IDENTITY.name}), acting under our service account — not a human.`,
      `We charged $${dollars} for invoice ${invoiceId}.`,
      ``,
      `If something looks wrong, reply and a human on the billing team will review.`,
    ].join("\n"),
  };
}
