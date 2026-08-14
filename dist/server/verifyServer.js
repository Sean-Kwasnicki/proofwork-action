import http from "node:http";
import os from "node:os";
import path from "node:path";
import { verifyRegistryEntry } from "../registry.js";
import { describeBinding } from "../bundle.js";
import { issuerPublicKey } from "../license.js";
import { readLog } from "../registry.js";
import { clearRevocationCache, fetchRevocationList, readRevocationList, revocationStatusFor, verifyRevocationList, writeRevocationList, REVOCATION_PATH, } from "../revocation.js";
/**
 * The hosted verify service.
 *
 * ## What this is for
 *
 * `proofwork verify record.json` already works and needs nothing from us. That is
 * the right primitive and the wrong sales surface: it requires the person doing
 * due diligence to install Node, obtain a file from the party they are checking,
 * and run a command. Buyers do not do that.
 *
 * What they do is open a link. This serves one: `/verify/PW-XXXX-XXXX-XXXX`
 * returns subject, verdict, commit, and expiry, for anyone, with no account.
 *
 * ## What it deliberately does not become
 *
 * It is **not** the authority. The signature is, and it travels with the record.
 * If this service is down, or gone, or acquired by someone else, every record
 * ever issued remains verifiable offline with the public key compiled into every
 * copy of the CLI. Building a verifier that *only* worked here would make our
 * uptime a precondition of our customers' due-diligence conversations, and would
 * quietly convert a cryptographic claim into a hosted one.
 *
 * So this endpoint re-runs exactly the same check the CLI does, over the same
 * signature, and says so on the page.
 *
 * ## Privacy
 *
 * A record is looked up by an id its holder chose to share. Nothing here
 * enumerates: there is no list endpoint, and an unknown id returns the same
 * response shape as a known one so the service cannot be walked to discover who
 * our customers are.
 */
const REGISTRY_LOG = () => process.env.PROOFWORK_REGISTRY_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "registry.jsonl");
/** Record ids are a fixed alphabet — anything else is not worth a disk read. */
const RECORD_ID = /^PW-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$/;
/**
 * Look up and verify a record.
 *
 * The log is read per request rather than cached. A cached registry would keep
 * serving a record after it was corrected or withdrawn, and correctness matters
 * more here than a few milliseconds — this endpoint is called by humans reading a
 * page, not in a hot loop.
 */
export function lookupRecord(recordId, logPath = REGISTRY_LOG(), revocationPath) {
    const unchecked = { revoked: false, revocation_checked: false, revocation_note: "" };
    if (!RECORD_ID.test(recordId)) {
        return { found: false, valid: false, expired: false, ...unchecked, errors: ["Not a valid record id."] };
    }
    let log = [];
    try {
        log = readLog(logPath);
    }
    catch (e) {
        return {
            found: false,
            valid: false,
            expired: false,
            ...unchecked,
            errors: [`Registry unavailable: ${e instanceof Error ? e.message : String(e)}`],
        };
    }
    const entry = log.find((r) => r.record_id === recordId);
    if (!entry) {
        return { found: false, valid: false, expired: false, ...unchecked, errors: ["No such record."] };
    }
    const pub = issuerPublicKey();
    if (!pub) {
        return {
            found: true, valid: false, expired: false, ...unchecked, entry,
            errors: ["No issuer key in this build."],
        };
    }
    const res = verifyRegistryEntry(entry, pub);
    /**
     * Revocation is checked here, not folded into `verifyRegistryEntry`.
     *
     * Those are two different questions — "did we issue this?" and "do we still
     * stand behind it?" — and the first must stay answerable offline with nothing
     * but the public key. Merging them would make the signature check depend on
     * having a current list, which is the network dependency this service exists
     * to avoid being.
     *
     * A revoked record is invalid regardless of its signature. That is what failing
     * closed means, and it is the one direction where no other property rescues it.
     */
    const revocation = revocationStatusFor(recordId, readRevocationList(revocationPath ?? REVOCATION_PATH()), pub);
    const errors = [...res.errors];
    if (revocation.revoked)
        errors.unshift(`Withdrawn by the issuer. ${revocation.note}`);
    return {
        found: true,
        valid: res.ok && !revocation.revoked,
        expired: res.expired,
        revoked: revocation.revoked,
        revocation_checked: revocation.checked,
        revocation_note: revocation.note,
        entry,
        errors,
    };
}
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/**
 * The page a buyer sees.
 *
 * Self-contained — no script, no external font, no remote image. A verification
 * page that loaded third-party assets would leak every due-diligence check
 * anyone ever ran to whoever hosts those assets.
 */
export function verifyPage(recordId, r) {
    const ok = r.found && r.valid;
    const passed = r.entry?.verdict === "pass";
    // Revocation is named before anything else. "DOES NOT VERIFY" would be true but
    // misleading — it reads as tampering or a typo, when what happened is that the
    // issuer withdrew a record it had genuinely signed.
    const headline = !r.found
        ? "NOT FOUND"
        : r.revoked
            ? "WITHDRAWN"
            : !r.valid
                ? "DOES NOT VERIFY"
                : passed
                    ? "CERTIFIED"
                    : "DENIED";
    const tone = !ok ? "bad" : passed ? "ok" : "warn";
    // Named for what the record is actually bound to. Saying "the commit above" on
    // a bundle-bound record sends the reader looking for a git commit that does
    // not exist for this proof.
    const isBundle = r.entry ? describeBinding(r.entry).kind === "bundle" : false;
    const boundNoun = isBundle ? "the bundle digest above" : "the commit above";
    // Kept specific per binding rather than flattened to one generic sentence. For a
    // commit-bound record "a later commit may have fixed the findings" is the exact
    // and useful statement; replacing it with "later code" to cover both cases would
    // have made the common case vaguer to accommodate the rarer one.
    const laterFix = isBundle
        ? "A later version may have fixed the findings."
        : "A later commit may have fixed the findings.";
    const rows = r.entry
        ? [
            ["Issued to", r.entry.subject],
            ["Verdict", r.entry.verdict === "pass" ? "PASS" : "FAIL"],
            ["Integrity", `${r.entry.integrity_score}/100`],
            ["Assertions", r.entry.assertions],
            [describeBinding(r.entry).label, describeBinding(r.entry).value],
            ["Issued", (r.entry.issued_at ?? "").slice(0, 10)],
            ["Expires", (r.entry.expires_at ?? "").slice(0, 10)],
        ]
        : [];
    return `<!doctype html>
<meta charset="utf-8">
<title>Proofwork — ${esc(recordId)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<style>
  :root{--ink:#070a09;--edge:rgba(255,255,255,.10);--white:#eef5f2;--grey:#9db3ab;
        --green:#3ef58f;--gold:#c9a961;--red:#e0554f}
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--ink);color:var(--white);min-height:100vh;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;line-height:1.6}
  .wrap{max-width:min(660px,100%);margin:0 auto;padding:56px 20px 72px}
  .mark{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:.3em;
    text-transform:uppercase;color:var(--gold)}
  h1{font-size:clamp(1.8rem,5vw,2.6rem);margin:16px 0 6px;letter-spacing:-.02em}
  h1.ok{color:var(--green)} h1.warn{color:var(--gold)} h1.bad{color:var(--red)}
  .id{font-family:ui-monospace,Menlo,monospace;color:var(--grey);margin:0 0 30px}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th{text-align:left;font-family:ui-monospace,Menlo,monospace;font-size:11px;
    letter-spacing:.16em;text-transform:uppercase;color:var(--grey);
    padding:12px 0;border-bottom:1px solid var(--edge);font-weight:500;width:36%}
  td{padding:12px 0;border-bottom:1px solid rgba(255,255,255,.05);
    font-family:ui-monospace,Menlo,monospace;font-size:.88rem;word-break:break-all}
  .note{margin-top:32px;padding:18px 20px;border:1px solid var(--edge);
    border-radius:10px;color:var(--grey);font-size:.9rem}
  .note b{color:var(--white);font-weight:600}
  code{font-family:ui-monospace,Menlo,monospace;color:var(--green)}
</style>
<div class="wrap">
  <div class="mark">Proofwork · Independent Verification</div>
  <h1 class="${tone}">${esc(headline)}</h1>
  <p class="id">${esc(recordId)}</p>

  ${rows.length ? `<table>${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</table>` : ""}

  ${r.revoked
        ? `<div class="note"><b>This certificate has been withdrawn by the issuer.</b><br>${esc(r.revocation_note)}<br><br>The signature on the record is genuine — we did issue it. We have since
         withdrawn it, and it should not be relied on.</div>`
        : ""}

  ${r.errors.length && !r.revoked
        ? `<div class="note"><b>Why this did not verify.</b><br>${r.errors.map(esc).join("<br>")}</div>`
        : ""}

  ${r.found && !r.revoked
        ? `<div class="note"><b>Withdrawal check.</b> ${esc(r.revocation_note)}${r.revocation_checked
            ? ""
            : " A record that could not be checked against the withdrawal list is not thereby cleared."}</div>`
        : ""}

  <div class="note">
    <b>This page is a convenience, not the authority.</b> The signature is, and it
    travels with the record. Anyone can check it without this site and without
    trusting us:
    <br><br>
    <code>proofwork verify &lt;record.json&gt;</code>
    <br><br>
    If this service disappeared tomorrow, every record ever issued would remain
    verifiable offline against the public key compiled into every copy of the CLI.
  </div>

  <div class="note">
    <b>Said carefully.</b> ${passed
        ? `This attests that the code at ${esc(boundNoun)} cleared the checks that applied to it.`
        : `This attests that the code at ${esc(boundNoun)} did not clear the checks that applied to it. ${esc(laterFix)}`}
    It describes one exact state and makes no claim about any other. It is not a
    statement that the software is safe, and it is not a conformity assessment
    under any statute.
  </div>
</div>
`;
}
/**
 * Start the verify service.
 *
 * Deliberately dependency-free and tiny. This process holds no secrets — it reads
 * a log and a public key, and can be run anywhere without the issuer private key
 * being present. Keeping the signing machine and the public-facing machine
 * separate is the whole point of the split.
 */
export function createVerifyServer(opts = {}) {
    const logPath = opts.logPath ?? REGISTRY_LOG();
    return http.createServer((req, res) => {
        const url = new URL(req.url ?? "/", "http://localhost");
        const wantsJson = url.searchParams.get("format") === "json" || (req.headers.accept ?? "").includes("application/json");
        if (url.pathname === "/healthz") {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        const match = /^\/verify\/([^/]+)\/?$/.exec(url.pathname);
        if (!match) {
            res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
            res.end("Usage: /verify/PW-XXXX-XXXX-XXXX\n");
            return;
        }
        const recordId = decodeURIComponent(match[1]).toUpperCase();
        const result = lookupRecord(recordId, logPath, opts.revocationPath);
        // 200 for a found-but-invalid record: the lookup succeeded and the answer is
        // "this does not verify". Returning 4xx would make a tampered record
        // indistinguishable from a typo to anything reading status codes.
        const status = result.found ? 200 : 404;
        if (wantsJson) {
            res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
            res.end(JSON.stringify({ record_id: recordId, ...result }, null, 2));
            return;
        }
        res.writeHead(status, {
            "content-type": "text/html; charset=utf-8",
            // No third-party anything. The page is self-contained by construction and
            // the policy states it, so a future edit that adds a CDN font fails loudly.
            "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff",
        });
        res.end(verifyPage(recordId, result));
    });
}
/**
 * Keep the local withdrawal list current from the issuer's published copy.
 *
 * The refresher writes to the same file `lookupRecord` already reads, so nothing
 * downstream changes and the file doubles as the cache. If the issuer is
 * unreachable, the previous file stays in place and verification continues
 * against it — degraded to "possibly stale", which the list's own `next_update`
 * makes visible, rather than failing.
 *
 * Verifying the signature before writing matters: without it, anything able to
 * answer that URL could plant a file that this service then treats as its
 * withdrawal list. The signature check downstream would still reject it, but the
 * good list would have been overwritten by then — a way to erase revocations
 * without holding the key.
 */
export function startRevocationRefresh(opts) {
    const pull = async () => {
        clearRevocationCache();
        const list = await fetchRevocationList(opts.url);
        if (!list)
            return;
        const pub = issuerPublicKey();
        if (!pub || !verifyRevocationList(list, pub).ok) {
            process.stderr.write("[proofwork] refused a withdrawal list that did not verify — keeping the previous one\n");
            return;
        }
        try {
            writeRevocationList(list, opts.file);
        }
        catch {
            // Read-only disk. Verification still works against whatever is there.
        }
    };
    void pull();
    const timer = setInterval(() => void pull(), opts.intervalMs ?? 60_000);
    // Do not hold the process open for a refresh loop.
    timer.unref?.();
    return timer;
}
/** Entry point for `node dist/server/verifyServer.js`. */
export function main() {
    const port = Number(process.env.PORT ?? 8787);
    const revocationUrl = process.env.PROOFWORK_REVOCATION_URL ?? "";
    if (revocationUrl) {
        startRevocationRefresh({ url: revocationUrl, file: REVOCATION_PATH() });
    }
    const server = createVerifyServer({ port });
    server.listen(port, () => {
        process.stdout.write(`\n  Proofwork verify service on :${port}\n` +
            `    http://localhost:${port}/verify/PW-XXXX-XXXX-XXXX\n` +
            `    http://localhost:${port}/healthz\n\n` +
            (revocationUrl
                ? `  Withdrawal list refreshed every 60s from ${revocationUrl}\n` +
                    `  Signatures are checked before it is accepted, so an unreachable or\n` +
                    `  tampered source leaves the previous list in place.\n\n`
                : `  PROOFWORK_REVOCATION_URL is not set. Verification will report the\n` +
                    `  withdrawal check as not run unless a list is present on disk.\n\n`) +
            `  Reads the registry log and the public key. Holds no secrets — the\n` +
            `  issuer private key is not needed here and must not be deployed with it.\n\n`);
    });
}
// Run only when invoked directly, so importing this module in a test does not
// bind a port.
if (process.argv[1] && /verifyServer\.js$/.test(process.argv[1]))
    main();
