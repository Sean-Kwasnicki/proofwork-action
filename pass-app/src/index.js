import { chargeInvoice } from "./charge.js";
import { DAILY_SPEND_CEILING_CENTS, IDENTITY } from "./config.js";

/** Unattended entrypoint — cron every hour. */
export async function run(client, invoices) {
  const results = [];
  for (const inv of invoices) {
    results.push(await chargeInvoice(client, inv));
  }
  return { agent: IDENTITY.name, ceilingCents: DAILY_SPEND_CEILING_CENTS, results };
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  console.log(JSON.stringify({ ready: true, agent: IDENTITY.name }));
}
