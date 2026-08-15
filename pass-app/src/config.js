export const IDENTITY = {
  name: "billing-sync",
  serviceKeyEnv: "AGENT_STRIPE_KEY",
  mailbox: "billing-sync@agents.example.com",
};

/** Hard ceiling — enforced in charge path, not just documentation. */
export const DAILY_SPEND_CEILING_CENTS = 50_000;
export const APPROVAL_THRESHOLD_CENTS = 10_000;

export function requireServiceKey(env = process.env) {
  const key = env[IDENTITY.serviceKeyEnv];
  if (!key) throw new Error(`Missing ${IDENTITY.serviceKeyEnv}; refusing to use user credentials`);
  if (env.USER_STRIPE_CUSTOMER_ID || env.SAVED_CARD_TOKEN) {
    throw new Error("Refusing customer/user payment credentials; service identity only");
  }
  return key;
}
