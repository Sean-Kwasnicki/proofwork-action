import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chargeInvoice } from "../src/charge.js";
import { receiptEmail } from "../src/mail.js";
import { DAILY_SPEND_CEILING_CENTS } from "../src/config.js";

function tmpLog() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "bs-")), "audit.jsonl");
}

const env = { AGENT_STRIPE_KEY: "sk_test_service_billing_sync" };

test("charges under ceiling and records durable audit", async () => {
  const logPath = tmpLog();
  const client = {
    async createCharge({ amountCents, apiKey }) {
      assert.equal(apiKey, env.AGENT_STRIPE_KEY);
      return { id: "ch_1", amountCents };
    },
  };
  const res = await chargeInvoice(
    client,
    { invoiceId: "inv_1", amountCents: 2500, customerEmail: "a@ex.com" },
    { env, logPath },
  );
  assert.equal(res.ok, true);
  assert.equal(res.audit.amountCents, 2500);
  assert.match(fs.readFileSync(logPath, "utf8"), /"succeeded"/);
});

test("blocks when daily ceiling would be exceeded", async () => {
  const logPath = tmpLog();
  fs.writeFileSync(
    logPath,
    JSON.stringify({
      ts: new Date().toISOString(),
      type: "charge",
      status: "succeeded",
      amountCents: DAILY_SPEND_CEILING_CENTS - 100,
    }) + "\n",
  );
  const client = { async createCharge() { throw new Error("should not charge"); } };
  const res = await chargeInvoice(
    client,
    { invoiceId: "inv_2", amountCents: 500, customerEmail: "a@ex.com" },
    { env, logPath },
  );
  assert.equal(res.status, "blocked_ceiling");
});

test("queues human review above approval threshold", async () => {
  const logPath = tmpLog();
  const res = await chargeInvoice(
    { async createCharge() { throw new Error("no"); } },
    { invoiceId: "inv_3", amountCents: 15_000, customerEmail: "a@ex.com" },
    { env, logPath },
  );
  assert.equal(res.status, "awaiting_human");
});

test("receipt discloses AI identity", () => {
  const mail = receiptEmail({ to: "a@ex.com", invoiceId: "inv_9", amountCents: 100 });
  assert.match(mail.body, /AI billing agent/i);
});

test("refuses user saved-card credentials", async () => {
  await assert.rejects(
    () =>
      chargeInvoice(
        { async createCharge() {} },
        { invoiceId: "x", amountCents: 100, customerEmail: "a@ex.com" },
        { env: { AGENT_STRIPE_KEY: "sk", SAVED_CARD_TOKEN: "tok_user" }, logPath: tmpLog() },
      ),
    /Refusing customer/,
  );
});
