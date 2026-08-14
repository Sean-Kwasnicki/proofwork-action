/**
 * Stripe access.
 *
 * ## Three rules this module exists to enforce
 *
 * **1. A key is never in code, never in the repository, never in a log.**
 * The only source is the environment. There is no parameter to pass one in, no
 * config field to set one, and no code path that writes one anywhere. This is not
 * caution for its own sake — our own gate fails a repository for exactly the
 * shape of mistake this prevents, and a payments module that leaked a key would
 * make the product a liar.
 *
 * **2. Nothing here can move real money by accident.**
 * Live keys are rejected outright unless the caller opts in explicitly. A `sk_live`
 * key found in the environment during development is treated as a mistake to
 * report, not permission to proceed.
 *
 * **3. It works with no key at all.**
 * Pointed at `stripe-mock`, the whole path is exercisable offline, in CI, with no
 * account and no credentials. That is what makes the payment code testable by the
 * same standard as everything else here rather than being the one corner nobody
 * can run.
 *
 * ## Why no `stripe` package
 *
 * This project holds a zero-dependency discipline, and Stripe's REST API is
 * form-encoded HTTP that `fetch` handles in a few lines. Taking a dependency —
 * and its transitive tree — into the module that touches payments, in a product
 * whose job is auditing supply chains, would be difficult to defend.
 */
const LIVE_PREFIX = /^sk_live_|^rk_live_/;
const TEST_PREFIX = /^sk_test_|^rk_test_/;
/**
 * Resolve how this process can talk to Stripe.
 *
 * Deliberately total: every combination of environment returns a config with a
 * mode and a human-readable reason, rather than throwing. An operator debugging
 * a payment problem needs to be told what state they are in, and a thrown error
 * that says "missing key" when the real problem is a live key in a test build
 * sends them the wrong way.
 */
export function resolveStripe(env = process.env) {
    const explicitBase = env.STRIPE_API_BASE?.trim();
    const key = env.STRIPE_SECRET_KEY?.trim() || null;
    // An explicit base pointing at a local mock wins over everything. This is how
    // CI runs: no key, no account, full coverage of the payment path.
    if (explicitBase && /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(explicitBase)) {
        return {
            mode: "mock",
            baseUrl: explicitBase.replace(/\/$/, ""),
            secretKey: key ?? "sk_test_mock",
            reason: `STRIPE_API_BASE points at ${explicitBase} — using a local mock, no real account involved.`,
        };
    }
    if (!key) {
        return {
            mode: "unconfigured",
            baseUrl: "https://api.stripe.com",
            secretKey: null,
            reason: "No STRIPE_SECRET_KEY in this environment. Getting a key from the Stripe dashboard is not " +
                "the same as putting it in this machine's environment — the key has to be set here for any " +
                "process to see it.",
        };
    }
    if (LIVE_PREFIX.test(key)) {
        // Reachable only by deliberate opt-in. Defaulting to "proceed" on a live key
        // is how a test run becomes a real charge, and there is no undo for that.
        if (env.PROOFWORK_ALLOW_LIVE_STRIPE !== "1") {
            return {
                mode: "unconfigured",
                baseUrl: "https://api.stripe.com",
                secretKey: null,
                reason: "A LIVE Stripe key is present and has been refused. Live keys move real money and nothing " +
                    "here needs that. Use a test key (sk_test_…), or set PROOFWORK_ALLOW_LIVE_STRIPE=1 if you " +
                    "genuinely intend to transact.",
            };
        }
        return {
            mode: "live",
            baseUrl: "https://api.stripe.com",
            secretKey: key,
            reason: "LIVE mode — real money. Enabled explicitly via PROOFWORK_ALLOW_LIVE_STRIPE=1.",
        };
    }
    if (TEST_PREFIX.test(key)) {
        return {
            mode: "test",
            baseUrl: "https://api.stripe.com",
            secretKey: key,
            reason: "Test-mode key detected — calls reach Stripe but no real money moves.",
        };
    }
    return {
        mode: "unconfigured",
        baseUrl: "https://api.stripe.com",
        secretKey: null,
        reason: "STRIPE_SECRET_KEY is set but is not a recognised Stripe secret key. Expected it to begin " +
            "sk_test_, rk_test_, or sk_live_. A publishable key (pk_…) will not work here — it is the " +
            "public half and cannot authenticate API calls.",
    };
}
/** Stripe takes form-encoded bodies, including for nested objects. */
export function encodeForm(params, prefix = "") {
    const parts = [];
    for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null)
            continue;
        const key = prefix ? `${prefix}[${k}]` : k;
        if (typeof v === "object" && !Array.isArray(v)) {
            parts.push(encodeForm(v, key));
        }
        else if (Array.isArray(v)) {
            v.forEach((item, i) => {
                if (typeof item === "object" && item !== null) {
                    parts.push(encodeForm(item, `${key}[${i}]`));
                }
                else {
                    parts.push(`${encodeURIComponent(`${key}[${i}]`)}=${encodeURIComponent(String(item))}`);
                }
            });
        }
        else {
            parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(v))}`);
        }
    }
    return parts.filter(Boolean).join("&");
}
/**
 * One request to Stripe.
 *
 * Errors are returned rather than thrown. A payment failure is an outcome the
 * caller has to handle — declined card, missing product, expired key — and
 * exceptions encourage a `catch` that swallows the reason, which is precisely the
 * pattern our own workmanship check fails people for.
 */
/**
 * The Stripe API version every request is pinned to.
 *
 * Overridable so an operator can move ahead of us without waiting for a release,
 * and so a version-specific bug can be worked around in configuration rather than
 * in a hotfix.
 */
export const STRIPE_API_VERSION = process.env.STRIPE_API_VERSION ?? "2025-03-31.basil";
export async function stripeRequest(path, opts = {}) {
    const config = opts.config ?? resolveStripe();
    if (!config.secretKey) {
        return { ok: false, status: 0, error: { message: config.reason, code: "not_configured" } };
    }
    const method = opts.method ?? "POST";
    const body = method === "POST" ? encodeForm(opts.params ?? {}) : undefined;
    const qs = method === "GET" && opts.params ? `?${encodeForm(opts.params)}` : "";
    const url = `${config.baseUrl}${path}${qs}`;
    const headers = {
        Authorization: `Bearer ${config.secretKey}`,
        "Content-Type": "application/x-www-form-urlencoded",
        // Pinned so a Stripe-side upgrade cannot silently change response shapes
        // under a running deployment.
        //
        // Raised from 2024-06-20 because Managed Payments — which Stripe now enables
        // by default on new accounts — is not supported before 2025-03-31.basil:
        //
        //     Managed Payments is not supported on API version 2024-06-20.
        //
        // Checkout was therefore impossible on any account carrying that default,
        // which is every account a new customer would open. Raising the pin keeps the
        // operator's own account setting intact; the alternative was passing
        // `managed_payments[enabled]=false` per session, which would override a
        // business decision about who is responsible for collecting tax — not a
        // choice this file should be making on someone's behalf.
        "Stripe-Version": STRIPE_API_VERSION,
    };
    if (opts.idempotencyKey)
        headers["Idempotency-Key"] = opts.idempotencyKey;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
    try {
        const res = await fetch(url, { method, headers, body, signal: controller.signal });
        const text = await res.text();
        let parsed;
        try {
            parsed = text ? JSON.parse(text) : {};
        }
        catch {
            return {
                ok: false,
                status: res.status,
                error: { message: `Stripe returned a non-JSON response (${res.status}).` },
            };
        }
        if (!res.ok) {
            const err = parsed.error;
            return {
                ok: false,
                status: res.status,
                error: {
                    message: err?.message ?? `Stripe request failed with ${res.status}.`,
                    ...(err?.type ? { type: err.type } : {}),
                    ...(err?.code ? { code: err.code } : {}),
                },
            };
        }
        return { ok: true, status: res.status, data: parsed };
    }
    catch (e) {
        const aborted = e instanceof Error && e.name === "AbortError";
        return {
            ok: false,
            status: 0,
            error: {
                message: aborted
                    ? `Stripe did not respond within ${opts.timeoutMs ?? 15_000}ms.`
                    : `Could not reach ${config.baseUrl}: ${e instanceof Error ? e.message : String(e)}`,
                code: aborted ? "timeout" : "network",
            },
        };
    }
    finally {
        clearTimeout(timer);
    }
}
/**
 * Answers one question: are we actually able to test, or not?
 *
 * It makes a real authenticated call, because every weaker signal lies. A key
 * being present says nothing about whether it works; a key looking well-formed
 * says nothing about whether it was rolled an hour ago. The only evidence that
 * settles it is a round trip.
 */
export async function stripeStatus(env = process.env) {
    const config = resolveStripe(env);
    if (config.mode === "unconfigured") {
        return { mode: config.mode, reason: config.reason, reachable: false };
    }
    const res = await stripeRequest("/v1/balance", {
        method: "GET",
        config,
        timeoutMs: 8_000,
    });
    if (!res.ok) {
        return {
            mode: config.mode,
            reason: config.reason,
            reachable: false,
            ...(res.error?.message ? { detail: res.error.message } : {}),
        };
    }
    return {
        mode: config.mode,
        reason: config.reason,
        reachable: true,
        ...(res.data?.livemode !== undefined ? { livemode: res.data.livemode } : {}),
    };
}
/** Rendered for a human who wants a yes or no. */
export function renderStripeStatus(s) {
    const verdict = s.reachable
        ? s.mode === "mock"
            ? "YES — running against a local mock. No account, no money, fully testable."
            : s.mode === "test"
                ? "YES — connected to Stripe in test mode. No real money can move."
                : "YES — connected in LIVE mode. Real money will move."
        : "NO — not able to reach Stripe.";
    const lines = [
        "",
        "  STRIPE CONNECTIVITY",
        `  ${"─".repeat(66)}`,
        "",
        `  Testing?  ${verdict}`,
        "",
        `  Mode      ${s.mode}`,
        `  Reachable ${s.reachable ? "yes — an authenticated call succeeded" : "no"}`,
    ];
    if (s.livemode !== undefined) {
        lines.push(`  Livemode  ${s.livemode ? "TRUE — this is a real account" : "false — test data only"}`);
    }
    lines.push("", `  ${s.reason}`);
    if (s.detail)
        lines.push("", `  Stripe said: ${s.detail}`);
    if (!s.reachable && s.mode === "unconfigured") {
        lines.push("", "  To connect:", "", "    setx STRIPE_SECRET_KEY \"sk_test_your_key\"", "", "  Then open a NEW terminal — setx does not affect windows that are already", "  running. Getting the key from the dashboard is not enough on its own; it", "  has to be set in this machine's environment for any process to see it.", "", "  Or test with no key and no account at all:", "", "    npx stripe-mock            # in one terminal", "    setx STRIPE_API_BASE http://localhost:12111");
    }
    lines.push("");
    return lines.join("\n");
}
