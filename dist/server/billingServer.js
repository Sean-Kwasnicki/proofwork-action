import http from "node:http";
import { fulfilWebhook, readFulfilments, webhookSecretFingerprint } from "../payments/fulfil.js";
import { readRevocationList, republishRevocationList } from "../revocation.js";
import { createCheckoutSession, verifyWebhookSignature } from "../payments/checkout.js";
import { resolveStripe } from "../payments/stripe.js";
import { isPlausibleEmail } from "../account.js";
import { loadOrCreateIssuerKeys } from "../issuer.js";
import { installIssuerKeyFromEnv, issuerReadiness, renderReadiness } from "./issuerReadiness.js";
import { deliverLicence, mailConfigured, readDeliveries, undelivered, } from "../payments/licenceMail.js";
/**
 * The billing endpoint.
 *
 * ## Why this is not part of the verify service
 *
 * The verify service states that it holds no secrets and that the issuer private
 * key must not be deployed alongside it. That is a real property, not a comment:
 * it means the public-facing box can be compromised without anyone gaining the
 * ability to mint a licence or forge a registry record.
 *
 * Fulfilment signs licences, so it needs that key. Adding a webhook route to the
 * verify service would have put the signing key on the box serving pages to the
 * public and silently repealed the guarantee — while leaving the paragraph that
 * claims it in place, which is worse than never having claimed it.
 *
 * So there are two processes. It costs one more deployment. What it buys is that
 * the only process holding the key exposes exactly one route, which rejects
 * anything Stripe did not sign.
 *
 * ## Scope
 *
 * One route: `POST /stripe/webhook`. No dashboard, no lookup, no admin. Anything
 * that needs the key stays here and stays small enough to read in one sitting.
 */
/** Bodies are read raw — a parsed body cannot be signature-checked. */
function readBody(req, limitBytes = 1_000_000) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on("data", (c) => {
            size += c.length;
            // Unbounded reads let anyone exhaust memory on the box holding the key.
            if (size > limitBytes) {
                reject(new Error("Body too large."));
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        req.on("error", reject);
    });
}
/**
 * Parse the two fields, from either shape.
 *
 * A `fetch` from the site sends JSON; a plain HTML form sends url-encoded. Both
 * are supported because the form is the version that still works with scripting
 * disabled, and a payment path that needs JavaScript to exist is one more thing
 * between a customer and paying.
 */
function parseCheckoutBody(body, contentType) {
    if (contentType.includes("application/json")) {
        try {
            const j = JSON.parse(body);
            return {
                email: typeof j.email === "string" ? j.email : undefined,
                organisation: typeof j.organisation === "string" ? j.organisation : undefined,
            };
        }
        catch {
            return {};
        }
    }
    const p = new URLSearchParams(body);
    return {
        email: p.get("email") ?? undefined,
        organisation: p.get("organisation") ?? undefined,
    };
}
export function createBillingServer(opts = {}) {
    const secret = opts.webhookSecret ?? process.env.STRIPE_WEBHOOK_SECRET ?? "";
    return http.createServer((req, res) => {
        const url = new URL(req.url ?? "/", "http://localhost");
        if (url.pathname === "/healthz") {
            // Reports whether a secret is configured and which one, by fingerprint.
            // A billing endpoint running without a secret accepts nothing, and finding
            // that out from a customer who paid and got no licence is too late.
            //
            // It reports storage and signing key for the same reason. This endpoint
            // once answered `{"ok":true}` while every delivery died on `mkdir`, because
            // the only thing it inspected was the one thing that was not broken. The
            // two additions are exactly the two conditions under which a payment
            // arrives and no usable licence can come out of it.
            //
            // Still HTTP 200 when unready: the process is answering and the fault is
            // configuration. A 5xx here would make a platform health check recycle the
            // container, and a service that restarts every thirty seconds cannot be
            // diagnosed and cannot receive the webhook that is being retried.
            const readiness = issuerReadiness();
            const fulfilments = readFulfilments(opts.logPath);
            const deliveries = readDeliveries(opts.deliveryLogPath);
            res.writeHead(200, {
                "content-type": "application/json",
                // Read cross-origin by the success page, which uses `mail_configured` to
                // decide whether it may tell a customer to watch their inbox. Everything
                // here is already public: a fingerprint, a public key id, and counts.
                "access-control-allow-origin": "*",
            });
            res.end(JSON.stringify({
                ok: secret !== "" && readiness.ok,
                webhook_secret: secret === "" ? "MISSING" : webhookSecretFingerprint(secret),
                fulfilled: fulfilments.length,
                // Whether a licence can reach the buyer without a human. The success
                // page reads this rather than asserting a mailer that may not exist.
                mail_configured: mailConfigured(),
                // Paid customers still owed their key. A provider outage otherwise
                // looks exactly like a quiet week.
                mail_undelivered: undelivered(fulfilments, deliveries).length,
                // The public half only ever verifies; publishing it lets anyone confirm
                // from outside that this issuer signs with the key their client trusts.
                issuer_key: readiness.key.keyId,
                issuer_key_trusted: readiness.key.trusted,
                storage_writable: readiness.storage.writable,
                storage_dir: readiness.storage.dir,
                ...(readiness.blockers.length ? { blockers: readiness.blockers } : {}),
            }));
            return;
        }
        /**
         * The signed withdrawal list, served publicly.
         *
         * Serving it from here rather than from the verify service is not a layering
         * accident. The issuer holds the key and the list; the verify service holds
         * neither, and the two run on separate machines with separate disks, so a
         * list written by the issuer would otherwise never reach the verifier — it
         * would take a redeploy to propagate a revocation, which is not revocation.
         *
         * No authentication, deliberately. The list is signed, so its distribution
         * channel does not need to be trusted: a hostile proxy can withhold it or
         * corrupt it, and both of those are *detected* — a corrupt list fails
         * signature verification and is treated as no list rather than an empty one,
         * and a withheld one leaves the checker saying the question went unanswered.
         * What no proxy can do is forge a withdrawal or erase one.
         */
        if (url.pathname === "/revocations.json" && req.method === "GET") {
            const list = readRevocationList(opts.revocationPath);
            if (!list) {
                res.writeHead(404, { "content-type": "application/json" });
                res.end(JSON.stringify({ error: "No revocation list has been published." }));
                return;
            }
            res.writeHead(200, {
                "content-type": "application/json; charset=utf-8",
                // Short, because this is the freshness path for revocation. The list
                // carries its own next_update, so a checker can tell staleness anyway,
                // but caching it for hours here would blunt the one lever that works
                // without a redeploy.
                "cache-control": "public, max-age=60",
                "access-control-allow-origin": "*",
            });
            res.end(JSON.stringify(list));
            return;
        }
        /**
         * Start a checkout. This is the route that makes the product self-serve.
         *
         * ## Why it lives here and nowhere else
         *
         * Creating a session needs the Stripe secret key, and this is the only
         * process that holds one. The verify service is deliberately keyless and the
         * site is static, so neither can do it — putting a key on either to save a
         * hop would hand it to the box serving pages to the public.
         *
         * ## What it does not touch
         *
         * Card details. The buyer is sent to Stripe's hosted Checkout, so nothing
         * here ever sees a card number, and a mistake in this file cannot leak one.
         *
         * ## The organisation name is load-bearing
         *
         * It becomes `client_reference_id`, which the webhook reads back to decide
         * who the licence is issued to — and `whoami` refuses a licence whose subject
         * does not match the organisation signed in. Send the wrong value and the
         * customer pays and then sees the free tier, which is the worst first run
         * available.
         */
        if (url.pathname === "/checkout") {
            // A cross-origin form post from the site needs no preflight, but a `fetch`
            // with a JSON content type does.
            if (req.method === "OPTIONS") {
                res.writeHead(204, {
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "POST, OPTIONS",
                    "access-control-allow-headers": "content-type",
                    "access-control-max-age": "600",
                });
                res.end();
                return;
            }
            if (req.method !== "POST") {
                res.writeHead(405, { "content-type": "application/json" });
                res.end(JSON.stringify({ error: "POST an email and organisation to /checkout." }));
                return;
            }
            void readBody(req)
                .then(async (body) => {
                const contentType = String(req.headers["content-type"] ?? "");
                const wantsJson = contentType.includes("application/json") ||
                    String(req.headers.accept ?? "").includes("application/json");
                const fail = (status, error) => {
                    res.writeHead(status, {
                        "content-type": "application/json",
                        "access-control-allow-origin": "*",
                    });
                    res.end(JSON.stringify({ error }));
                };
                const parsed = parseCheckoutBody(body, contentType);
                const organisation = (parsed.organisation ?? "").trim();
                const email = (parsed.email ?? "").trim();
                // Both are refused with the reason, not a generic 400. Whoever hits
                // this is trying to give us money and cannot see our logs.
                if (!organisation) {
                    fail(400, "An organisation name is required. It is printed on the certificate and signed " +
                        "into the record, and it is what your licence is matched against.");
                    return;
                }
                if (!email) {
                    fail(400, "An email address is required. Stripe sends the receipt there.");
                    return;
                }
                if (!isPlausibleEmail(email)) {
                    fail(400, `"${email}" does not look like an email address.`);
                    return;
                }
                const site = opts.siteUrl ?? process.env.PROOFWORK_SITE_URL ?? "";
                const config = opts.stripeConfig ?? resolveStripe();
                const created = await createCheckoutSession({
                    // One tier is sold self-serve, and its price comes from the shared
                    // price book so the amount charged cannot drift from the amount on
                    // the page.
                    tier: "assured",
                    email,
                    reference: organisation,
                    successUrl: site ? `${site.replace(/\/$/, "")}/paid.html` : "https://stripe.com",
                    cancelUrl: site ? `${site.replace(/\/$/, "")}/#offer` : "https://stripe.com",
                    config,
                });
                if (!created.ok) {
                    // Stripe's own message, forwarded. A generic "checkout failed" would
                    // strand an operator debugging a misconfigured account.
                    fail(502, created.error);
                    return;
                }
                if (wantsJson) {
                    res.writeHead(200, {
                        "content-type": "application/json",
                        "access-control-allow-origin": "*",
                    });
                    res.end(JSON.stringify({
                        url: created.session.url,
                        session_id: created.session.id,
                        amount: created.session.amount,
                        currency: created.session.currency,
                        organisation: created.session.clientReferenceId,
                    }));
                    return;
                }
                // Plain form post: send the browser straight to Stripe. 303 so the
                // redirect is followed with GET rather than replaying the POST.
                res.writeHead(303, { location: created.session.url });
                res.end();
            })
                .catch((e) => {
                res.writeHead(500, {
                    "content-type": "application/json",
                    "access-control-allow-origin": "*",
                });
                res.end(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }));
            });
            return;
        }
        if (url.pathname !== "/stripe/webhook" || req.method !== "POST") {
            res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
            res.end("POST /checkout · POST /stripe/webhook\n");
            return;
        }
        if (secret === "") {
            // 500, not 400. The request may be perfectly good; we are misconfigured,
            // and a 4xx would tell Stripe to stop retrying a payment we can still fulfil
            // once the secret is set.
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: "STRIPE_WEBHOOK_SECRET is not set." }));
            return;
        }
        void readBody(req)
            .then(async (payload) => {
            /**
             * Refuse the delivery rather than mishandle the payment.
             *
             * Two conditions make minting wrong rather than merely difficult: a disk
             * that cannot be written, and a signing key that customers' clients will
             * not trust. Under either, the honest answer is 500 — Stripe keeps the
             * event and keeps retrying, so the payment can still be honoured once the
             * deployment is fixed.
             *
             * The alternative is worse in a way that is not recoverable. Minting
             * against an untrusted key returns 200, Stripe marks the event delivered
             * and stops, and the customer holds a well-formed licence that every CLI
             * rejects — with no event left to replay.
             *
             * Checked per delivery, not once at startup: a disk can be remounted
             * read-only, or fill up, long after the process came up healthy.
             *
             * The signature is verified first even here. An unsigned request must
             * still be refused as unsigned — being misconfigured is no reason to
             * start telling strangers our storage layout.
             */
            const readiness = issuerReadiness();
            if (!readiness.ok) {
                const sig = verifyWebhookSignature(payload, String(req.headers["stripe-signature"] ?? ""), secret);
                if (!sig.ok) {
                    res.writeHead(400, { "content-type": "application/json" });
                    res.end(JSON.stringify({
                        status: "rejected",
                        reason: sig.reason ?? "Signature did not verify.",
                    }));
                    return;
                }
                process.stderr.write(`[proofwork] REFUSED a signed delivery — issuer not ready:\n` +
                    readiness.blockers.map((b) => `  · ${b}\n`).join(""));
                res.writeHead(500, { "content-type": "application/json" });
                res.end(JSON.stringify({
                    status: "not_ready",
                    reason: "The issuer cannot mint a licence this customer could use. Stripe will " +
                        "retry, and the payment will be honoured once this is fixed.",
                    blockers: readiness.blockers,
                }));
                return;
            }
            const result = fulfilWebhook({
                payload,
                signatureHeader: String(req.headers["stripe-signature"] ?? ""),
                webhookSecret: secret,
                ...(opts.logPath !== undefined ? { logPath: opts.logPath } : {}),
            });
            // Status codes are how Stripe decides whether to retry, so they carry
            // meaning here beyond politeness:
            //   rejected → 400, never retry, the signature will not become valid
            //   ignored  → 200, we saw it and there is nothing to do
            //   fulfilled / already_fulfilled → 200, stop retrying
            const status = result.status === "rejected" ? 400 : 200;
            /**
             * Email the key, on a first mint only.
             *
             * `already_fulfilled` is deliberately excluded. That branch is Stripe
             * re-delivering an event we have already answered, and mailing from it
             * would send the same key again for one payment — every retry, forever.
             * The idempotency that protects the licence is the same one protecting
             * the email, rather than a second mechanism alongside it that can drift.
             *
             * Awaited, so a provider failure is recorded before this webhook is
             * answered rather than after the process may have moved on. Bounded by
             * the sender's own timeout, well inside what Stripe waits for.
             *
             * Never allowed to change the response. The licence is already minted
             * and recorded; failing the webhook now would make Stripe retry into
             * `already_fulfilled`, which sends nothing and leaves the payment
             * looking unfulfilled — strictly worse than an undelivered email we have
             * a record of.
             */
            if (result.status === "fulfilled") {
                // The key is not in this line. Hosting platforms retain stdout, and it
                // is a bearer credential.
                process.stdout.write(`[proofwork] fulfilled ${result.fulfilment.tier} for ${result.fulfilment.reference} ` +
                    `(${result.fulfilment.session_id})\n`);
                const delivery = await deliverLicence({
                    fulfilment: result.fulfilment,
                    ...(opts.mailSender !== undefined ? { send: opts.mailSender } : {}),
                    ...(opts.deliveryLogPath !== undefined ? { logPath: opts.deliveryLogPath } : {}),
                });
                if (delivery.status === "failed") {
                    process.stderr.write(`[proofwork] licence minted but NOT emailed to ${result.fulfilment.email} ` +
                        `(${result.fulfilment.session_id}): ${delivery.error}\n`);
                }
                else if (delivery.status === "skipped") {
                    process.stderr.write(`[proofwork] licence minted, delivery skipped (${result.fulfilment.session_id}): ` +
                        `${delivery.reason}\n`);
                }
            }
            res.writeHead(status, { "content-type": "application/json" });
            // The licence key is not echoed. Stripe stores webhook responses and the
            // key is a bearer credential; it is delivered to the buyer by the success
            // page and the receipt, not written into a third party's log.
            res.end(JSON.stringify({
                status: result.status,
                ...("reason" in result ? { reason: result.reason } : {}),
            }));
        })
            .catch((e) => {
            // 500 so Stripe retries — a transient read failure should not cost
            // somebody the licence they paid for.
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }));
        });
    });
}
/**
 * Publish an empty signed list if none exists yet.
 *
 * Without this, every verification from deploy day until the first real
 * revocation reports "Withdrawal NOT CHECKED". That is honest — nobody had
 * published anything to check against — but it reads to a buyer as an unfinished
 * feature, and it wastes the distinction: the warning is meant to mean "we could
 * not reach the list", not "the list does not exist yet".
 *
 * An empty signed list says something different and true: the issuer has
 * published, and nothing is withdrawn.
 *
 * Only ever creates. It will not overwrite an existing list, because doing so on
 * a restart would silently erase every withdrawal ever issued — the one bug in
 * this file that could not be recovered from.
 */
export function ensureRevocationListPublished(file) {
    if (readRevocationList(file))
        return "already";
    try {
        const keys = loadOrCreateIssuerKeys();
        republishRevocationList({
            privateKeyPem: keys.privateKeyPem,
            publicKeyPem: keys.publicKeyPem,
            ...(file !== undefined ? { file } : {}),
        });
        return "created";
    }
    catch {
        // A billing service that cannot write a list must still take payments.
        return "failed";
    }
}
/** Entry point for `node dist/server/billingServer.js`. */
export function main() {
    const port = Number(process.env.BILLING_PORT ?? process.env.PORT ?? 8788);
    const secret = process.env.STRIPE_WEBHOOK_SECRET ?? "";
    // Order matters here, and both steps must come before anything else touches
    // the issuer directory. `ensureRevocationListPublished` calls
    // `loadOrCreateIssuerKeys`, which generates a keypair on an empty disk — so
    // running it first would mean the deployment quietly adopts a key no customer
    // trusts, and readiness would then report that invented key as present.
    const install = installIssuerKeyFromEnv();
    const readiness = issuerReadiness();
    const published = ensureRevocationListPublished();
    createBillingServer({ port }).listen(port, () => {
        process.stdout.write(`\n  Proofwork billing service on :${port}\n` +
            `    POST http://localhost:${port}/stripe/webhook\n` +
            `    GET  http://localhost:${port}/revocations.json\n` +
            `    GET  http://localhost:${port}/healthz\n\n` +
            (published === "created"
                ? `  Published an empty signed withdrawal list. Verifiers can now tell\n` +
                    `  "nothing is withdrawn" from "nobody has said".\n\n`
                : published === "failed"
                    ? `  Could not publish a withdrawal list. Verification still works; it\n` +
                        `  will report the withdrawal check as not run.\n\n`
                    : "") +
            (secret === ""
                ? `  STRIPE_WEBHOOK_SECRET is NOT set. Every webhook will be refused and\n` +
                    `  no licence will be issued. Set it before pointing Stripe here.\n\n`
                : `  Webhook secret ${webhookSecretFingerprint(secret)} · this process holds the\n` +
                    `  issuer private key. Do not deploy it on the same box as the verify\n` +
                    `  service, which is public and must stay keyless.\n\n`) +
            // The install status names the key by id only. The key id is a hash of
            // the public half and is safe in a log an operator will paste into chat.
            (install.status === "installed" || install.status === "replaced"
                ? `  ${install.detail} Key ${install.keyId}.\n\n`
                : install.status === "invalid"
                    ? `  ${install.detail}\n\n`
                    : "") +
            renderReadiness(readiness));
    });
}
if (process.argv[1] && /billingServer\.js$/.test(process.argv[1]))
    main();
