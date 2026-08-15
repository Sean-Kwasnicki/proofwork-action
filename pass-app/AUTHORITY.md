> Operated by **Cascade Harbor Co.** for **Harborline Commerce Platform** / Harborline Billing.
> Certificate subject: Cascade Harbor Co.

# billing-sync authority

Identity: service account `billing-sync@agents.example.com` via `AGENT_STRIPE_KEY`.
Never use a customer's saved card or a human operator's personal Stripe session.

Limits:
- Daily spend ceiling: $500.00 (`DAILY_SPEND_CEILING_CENTS`)
- Single-charge approval threshold: $100.00 - above this, enqueue for human review
- May send billing receipts; must disclose AI identity in every outbound message
