import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { verifyRegistryEntry } from "./registry.js";
import { issuerPublicKey } from "./license.js";
import { loadAccount } from "./account.js";
/**
 * The credential vault — every certification a company holds, in one place.
 *
 * ## Why a vault beats a certificate
 *
 * A single certificate is a snapshot: this commit, this day. It answers "did they
 * pass once?", which is the weakest version of the question a buyer is asking.
 *
 * A vault answers a better one. Fourteen records across six months, each bound to
 * a different commit, each independently signed, is a *track record* — and a
 * track record is far harder to manufacture than a moment. Anyone can have one
 * good day; nobody accidentally has thirty.
 *
 * ## Read-only, and not because we say so
 *
 * The vault is not read-only by permission. Every record in it carries an issuer
 * signature over its own contents, so editing a score, a date, or a company name
 * invalidates that record — and the vault verifies each one every time it is
 * opened, rather than trusting what it stored.
 *
 * That distinction matters. A read-only *interface* is a promise from us. A
 * signature is a property of the artefact, and it survives being copied,
 * emailed, or re-hosted by someone we have never met. The vault could be handed
 * to a stranger on a USB stick and still be checkable.
 *
 * ## What it deliberately does not do
 *
 * It does not hide failures by omission and then imply completeness. The vault
 * shows what the holder has been issued; it cannot show runs that were never
 * certified, because those produce no record. Any summary drawn from it says
 * "these are the certifications held", never "this is every run performed" —
 * conflating the two would let a vault of three cherry-picked passes read as an
 * unbroken history.
 */
const VAULT_DIR = () => process.env.PROOFWORK_VAULT_DIR ?? path.join(os.homedir(), ".proofwork", "vault");
/** Store a record in the vault. Called whenever a credential is issued. */
export function depositCredential(entry) {
    const dir = VAULT_DIR();
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${entry.record_id}.json`);
    fs.writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`, "utf8");
    return file;
}
/**
 * Read and verify the whole vault.
 *
 * Every record is checked against the issuer key on every read. Storing a
 * "verified" flag at deposit time and trusting it later would mean a file edited
 * on disk afterwards continues to display as valid — which is exactly the
 * tamper this design exists to make impossible.
 */
export function openVault(publicKeyPem) {
    const pub = publicKeyPem ?? issuerPublicKey();
    const dir = VAULT_DIR();
    const account = loadAccount();
    let files = [];
    try {
        files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
    }
    catch {
        files = [];
    }
    const items = [];
    for (const f of files) {
        const file = path.join(dir, f);
        try {
            // Accepts both shapes: a certificate record is the entry itself, a denial
            // record nests it under `record` so it can carry unsigned reasons alongside.
            const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
            const entry = "record" in parsed && parsed.record ? parsed.record : parsed;
            if (!pub) {
                items.push({ entry, file, valid: false, expired: false, errors: ["No issuer key in this build."] });
                continue;
            }
            const res = verifyRegistryEntry(entry, pub);
            items.push({ entry, file, valid: res.ok, expired: res.expired, errors: res.errors });
        }
        catch (e) {
            // An unreadable file is surfaced rather than skipped. A vault that silently
            // drops what it cannot parse would under-report a tamper as an absence.
            items.push({
                entry: { record_id: path.basename(f, ".json") },
                file,
                valid: false,
                expired: false,
                errors: [`Could not read: ${e instanceof Error ? e.message : String(e)}`],
            });
        }
    }
    items.sort((a, b) => (b.entry.issued_at ?? "").localeCompare(a.entry.issued_at ?? ""));
    const dated = items.filter((i) => i.entry.issued_at).map((i) => i.entry.issued_at);
    const passing = (i) => i.entry.verdict === "pass";
    return {
        organisation: account?.organisation ?? items[0]?.entry.subject ?? "Unknown",
        items,
        // "Active" counts only current certificates. A denial that verifies is a
        // valid record and an inactive credential — conflating the two would let a
        // failing history inflate the headline number.
        active: items.filter((i) => i.valid && !i.expired && passing(i)).length,
        expired: items.filter((i) => i.expired).length,
        invalid: items.filter((i) => !i.valid && !i.expired).length,
        denied: items.filter((i) => i.valid && !passing(i)).length,
        firstIssued: dated.length ? dated[dated.length - 1] : null,
        latestIssued: dated.length ? dated[0] : null,
    };
}
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/** Rendered for a terminal. */
export function renderVault(v) {
    const rule = "─".repeat(74);
    if (v.items.length === 0) {
        return [
            "",
            "  CREDENTIAL VAULT",
            `  ${rule}`,
            "",
            "  Empty. A record is deposited each time a run is certified.",
            "",
            "    proofwork certificate --root <your repo>",
            "",
        ].join("\n");
    }
    const rows = v.items.map((i) => {
        const state = !i.valid
            ? "INVALID"
            : i.entry.verdict === "fail"
                ? "DENIED"
                : i.expired
                    ? "EXPIRED"
                    : "CERTIFIED";
        return (`  ${state.padEnd(10)} ${i.entry.record_id.padEnd(18)} ` +
            `${String(i.entry.integrity_score ?? "—").padStart(3)}/100  ` +
            `${(i.entry.issued_at ?? "").slice(0, 10)}  ${(i.entry.commit ?? "unbound").slice(0, 8)}`);
    });
    return [
        "",
        `  CREDENTIAL VAULT — ${v.organisation}`,
        `  ${rule}`,
        "",
        ...rows,
        "",
        `  ${rule}`,
        `  ${v.active} certified · ${v.denied} denied · ${v.expired} expired · ${v.invalid} invalid`,
        v.firstIssued ? `  History since ${v.firstIssued.slice(0, 10)}` : "",
        "",
        "  Every record above was re-verified against the issuer signature just now,",
        "  not trusted from storage. Editing any of these files invalidates it.",
        "",
        "  Denials are recorded here as well as passes. A vault of certificates alone",
        "  would show which runs succeeded and nothing about which did not.",
        "",
        "  Honest limit: this shows records that were issued. Someone who never runs",
        "  the gate produces no record at all, and no signature can fix that — but a",
        "  missing sequence number is a question a reader can ask.",
        "",
    ]
        .filter((l, idx, arr) => !(l === "" && arr[idx - 1] === ""))
        .join("\n");
}
/**
 * A shareable vault page.
 *
 * Self-contained: no script, no external font, no remote image. It is meant to be
 * emailed or hosted by the holder, and a page that fetched anything would leak
 * every viewer of every customer's credential page back to us.
 */
export function vaultHtml(v) {
    const row = (i) => {
        const denied = i.entry.verdict === "fail";
        const state = !i.valid ? "INVALID" : denied ? "DENIED" : i.expired ? "EXPIRED" : "CERTIFIED";
        const cls = !i.valid ? "bad" : denied ? "warn" : i.expired ? "dim" : "ok";
        return `<tr>
      <td class="mono ${cls}">${esc(state)}</td>
      <td class="mono">${esc(i.entry.record_id)}</td>
      <td>${esc(String(i.entry.integrity_score ?? "—"))}<span class="dim">/100</span></td>
      <td class="mono dim">${esc((i.entry.commit ?? "unbound").slice(0, 12))}</td>
      <td class="mono dim">${esc((i.entry.issued_at ?? "").slice(0, 10))}</td>
      <td class="mono dim">${esc((i.entry.expires_at ?? "").slice(0, 10))}</td>
    </tr>`;
    };
    return `<!doctype html>
<meta charset="utf-8">
<title>Proofwork credential vault — ${esc(v.organisation)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{--ink:#070a09;--ink2:#0b100e;--edge:rgba(255,255,255,.10);
        --white:#eef5f2;--grey:#9db3ab;--green:#3ef58f;--gold:#c9a961;--red:#e0554f}
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--ink);color:var(--white);min-height:100vh;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;line-height:1.6}
  .wrap{max-width:min(920px,100%);margin:0 auto;padding:48px 20px 72px}
  .mark{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:.3em;
    text-transform:uppercase;color:var(--gold)}
  h1{font-size:clamp(1.6rem,4vw,2.3rem);margin:14px 0 4px;letter-spacing:-.02em}
  .sub{color:var(--grey);margin:0 0 30px}
  .stats{display:flex;flex-wrap:wrap;gap:34px;padding:22px 0;border-top:1px solid var(--edge);
    border-bottom:1px solid var(--edge);margin-bottom:26px}
  .stat .k{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:.2em;
    text-transform:uppercase;color:var(--grey)}
  .stat .v{font-size:30px;font-weight:700;margin-top:4px}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:.92rem;min-width:640px}
  th{text-align:left;font-family:ui-monospace,Menlo,monospace;font-size:11px;
    letter-spacing:.16em;text-transform:uppercase;color:var(--grey);
    padding:10px 12px;border-bottom:1px solid var(--edge);font-weight:500}
  td{padding:13px 12px;border-bottom:1px solid rgba(255,255,255,.05)}
  .mono{font-family:ui-monospace,Menlo,monospace;font-size:.84rem}
  .dim{color:var(--grey)}
  .ok{color:var(--green)} .warn{color:var(--gold)} .bad{color:var(--red)}
  .note{margin-top:30px;padding:18px 20px;border:1px solid var(--edge);border-radius:10px;
    color:var(--grey);font-size:.9rem}
  .note b{color:var(--white);font-weight:600}
  @media print{ html,body{background:#fff;color:#111} .note{border-color:#ccc} }
</style>
<div class="wrap">
  <div class="mark">Proofwork · Credential Vault</div>
  <h1>${esc(v.organisation)}</h1>
  <p class="sub">${v.firstIssued ? `Certified since ${esc(v.firstIssued.slice(0, 10))}` : "No credentials yet"}</p>

  <div class="stats">
    <div class="stat"><div class="k">Certified</div><div class="v ok">${v.active}</div></div>
    <div class="stat"><div class="k">Denied</div><div class="v ${v.denied ? "warn" : "dim"}">${v.denied}</div></div>
    <div class="stat"><div class="k">Expired</div><div class="v dim">${v.expired}</div></div>
    <div class="stat"><div class="k">Invalid</div><div class="v ${v.invalid ? "bad" : "dim"}">${v.invalid}</div></div>
    <div class="stat"><div class="k">Total records</div><div class="v">${v.items.length}</div></div>
  </div>

  <div class="scroll">
    <table>
      <thead><tr><th>State</th><th>Record</th><th>Score</th><th>Commit</th><th>Issued</th><th>Expires</th></tr></thead>
      <tbody>${v.items.map(row).join("")}</tbody>
    </table>
  </div>

  <div class="note">
    <b>Read-only by construction.</b> Each record carries an issuer signature over its
    own contents and is re-verified whenever this page is generated — not trusted
    from storage. Changing a score, a date, or the organisation name invalidates
    that record, and it appears here as <span class="bad">INVALID</span>.
    <br><br>
    <b>Denials are shown, not hidden.</b> A vault containing only certificates would
    say which runs succeeded and nothing about which did not. Each <span class="warn">DENIED</span>
    record is signed exactly like a certificate and cannot be edited into a pass.
    <br><br>
    <b>Said carefully.</b> This lists records that were <em>issued</em>. Someone who
    never runs the gate produces no record at all, and no signature scheme can fix
    that — though a gap in the sequence is a question a reader can ask. Each record
    attests to one commit: a certificate says the code there cleared the checks that
    applied to it, a denial says it did not, and a later commit may have changed
    either. It is not a statement that the software is safe, and it is not a
    conformity assessment under any statute.
  </div>
</div>
`;
}
/** Write the shareable page. Returns its path. */
export function writeVaultPage(v, outFile) {
    const file = outFile ?? path.join(VAULT_DIR(), "vault.html");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, vaultHtml(v), "utf8");
    return file;
}
