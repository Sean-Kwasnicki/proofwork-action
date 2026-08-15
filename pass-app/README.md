This folder is a fixture, not a product.

It is the passing counterpart to `smoke-app`. GitHub Actions grades it with
`Sean-Kwasnicki/proofwork-action/.github/workflows/gate.yml@v1` so a signed
record can be deposited. The job is supposed to PASS. A red X here would mean
the unattended mint path is broken.

The app itself is Harborline Billing Sync: autonomous invoice charging under a
service Stripe key, with a daily ceiling, human review above a threshold, and
AI identity disclosed on every receipt.
