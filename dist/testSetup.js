import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateIssuerKeypair } from "./license.js";
/**
 * Keep the test suite out of the operator's real issuer directory.
 *
 * ## What went wrong
 *
 * A test exercised the billing webhook end to end without injecting a fake
 * issuer, so it called the real one — which signed a genuine licence and appended
 * it to `~/.proofwork-issuer/issued.jsonl`. That file is the record of what has
 * been sold. A test run put a sale in it that never happened.
 *
 * Nothing was corrupted and no key leaked, but the ledger that answers "what have
 * we sold?" acquired an answer that was untrue, and the entry is
 * indistinguishable from a real one because it was signed with the real key.
 *
 * ## Why the fix is here rather than in that test
 *
 * Fixing the one test would have left every future test one forgotten injection
 * away from the same thing, and the failure is silent — the suite passes either
 * way. The only signal is a stray line in a file nobody reads until they are
 * reconciling revenue.
 *
 * So the whole suite is pointed at a throwaway directory before any test runs.
 * A test that forgets to inject a fake issuer now writes somewhere harmless
 * instead of somewhere permanent.
 *
 * The directory is deliberately *not* deleted afterwards: it lives under the OS
 * temp directory, and a test that needs to inspect what it wrote can. The OS
 * reclaims it.
 */
const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "proofwork-test-issuer-"));
process.env.PROOFWORK_ISSUER_DIR = sandbox;
// Set explicitly rather than relying on them deriving from the directory above.
// Each is read through its own env var, and a future refactor that changes one
// default would otherwise reopen the hole quietly.
process.env.PROOFWORK_FULFILMENT_LOG = path.join(sandbox, "fulfilments.jsonl");
process.env.PROOFWORK_REGISTRY_LOG = path.join(sandbox, "registry.jsonl");
/**
 * Signing keys are generated fresh in the sandbox rather than copied.
 *
 * Copying the operator's private key into a temp directory to make tests pass
 * would put the key that mints every licence somewhere world-readable, to save
 * a few milliseconds of keygen.
 *
 * ## Why the public half is published to the environment
 *
 * Tests that sign a record and then verify it need both halves to agree. Signing
 * uses whatever key lives in `PROOFWORK_ISSUER_DIR`; verification uses
 * `issuerPublicKey()`, which returns the key compiled into the build. Before
 * isolation those were the same key by accident — the suite signed with the
 * operator's real private key, which matched the embedded public one — and five
 * tests quietly depended on that.
 *
 * That coupling was a latent bug in its own right: those tests would have failed
 * for anyone whose machine had a different issuer key, including a fresh clone
 * and CI. Generating the pair here and pointing the documented
 * `PROOFWORK_ISSUER_PUBKEY` override at its public half makes the suite
 * self-consistent and independent of whose machine it runs on.
 */
/**
 * No test may reach the mail provider.
 *
 * A billing test that forgot to inject a sender called the real Resend API,
 * because `RESEND_API_KEY` is set in the operator's environment. It failed with
 * a 403 only because the sending domain is still unverified — the moment that
 * domain is verified, the same test would email a customer-shaped address for
 * real, from a test run, with a licence key in the body.
 *
 * Same reasoning as the issuer directory above: fixing the one test would leave
 * every future test one forgotten injection away from sending mail. Clearing the
 * configuration here means `mailConfig()` returns null, delivery reports
 * "skipped", and forgetting is harmless.
 */
for (const key of ["RESEND_API_KEY", "PROOFWORK_MAIL_FROM", "RESEND_FROM"]) {
    delete process.env[key];
}
const keys = generateIssuerKeypair();
fs.writeFileSync(path.join(sandbox, "issuer-private.pem"), keys.privateKeyPem, "utf8");
fs.writeFileSync(path.join(sandbox, "issuer-public.pem"), keys.publicKeyPem, "utf8");
process.env.PROOFWORK_ISSUER_PUBKEY = keys.publicKeyPem;
export const TEST_ISSUER_DIR = sandbox;
