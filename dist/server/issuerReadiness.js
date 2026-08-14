import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { issuerPaths } from "../issuer.js";
import { issuerPublicKey } from "../license.js";
const keyIdOf = (pem) => crypto.createHash("sha256").update(pem.replace(/\s+/g, "")).digest("hex").slice(0, 16);
/** PEMs differ by line endings and trailing newlines across platforms. */
const normalisePem = (pem) => pem.replace(/\s+/g, "");
/**
 * Try the write that fulfilment will try.
 *
 * The probe file is per-process and random so two concurrent health checks
 * cannot delete each other's, and it is removed in a `finally` so a crash
 * between write and unlink cannot leave litter that looks like a fulfilment.
 */
export function checkIssuerStorage(dir = issuerPaths().dir) {
    const probe = path.join(dir, `.write-probe-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
    try {
        fs.mkdirSync(dir, { recursive: true });
        try {
            fs.writeFileSync(probe, "probe", "utf8");
        }
        finally {
            try {
                fs.rmSync(probe, { force: true });
            }
            catch {
                // Removing the probe is housekeeping. Failing to remove it does not
                // make the directory unwritable — the write above already proved it is.
            }
        }
        return { dir, writable: true, detail: `Writable: ${dir}` };
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
            dir,
            writable: false,
            detail: `Cannot write ${dir} — ${msg}. Fulfilment writes the licence ledger here ` +
                `before reporting success, so no payment can be honoured until this path ` +
                `is writable by the user running this process.`,
        };
    }
}
/**
 * Inspect the signing key without creating one.
 *
 * Deliberately not `loadOrCreateIssuerKeys`: calling that from a health check
 * would *cause* the failure it is meant to detect, generating an untrusted key
 * as a side effect of asking whether a trusted one exists.
 *
 * The comparison is against `issuerPublicKey()` rather than the embedded
 * constant directly, so it follows the documented `PROOFWORK_ISSUER_PUBKEY`
 * override. That keeps the check meaningful in development and under test, where
 * the anchor legitimately points at a sandbox key, while on the deployed issuer
 * — where no override is set — it compares against exactly the key every
 * customer's CLI carries.
 */
export function checkIssuerKey() {
    const paths = issuerPaths();
    const anchor = issuerPublicKey();
    let pem;
    try {
        pem = fs.readFileSync(paths.publicKey, "utf8");
    }
    catch {
        return {
            present: false,
            keyId: null,
            trusted: false,
            detail: `No issuer keypair at ${paths.dir}. The next mint would generate a new one, ` +
                `and licences signed with it fail verification in every client — which ships ` +
                `the public half compiled in. Copy the operator keypair onto this disk instead.`,
        };
    }
    const keyId = keyIdOf(pem);
    if (!fs.existsSync(paths.privateKey)) {
        return {
            present: false,
            keyId,
            trusted: false,
            detail: `Public key present but no private key at ${paths.privateKey}. Nothing can be signed.`,
        };
    }
    if (!anchor) {
        return {
            present: true,
            keyId,
            trusted: false,
            detail: "No trust anchor is configured, so nothing could verify a licence minted here.",
        };
    }
    const trusted = normalisePem(pem) === normalisePem(anchor);
    return {
        present: true,
        keyId,
        trusted,
        detail: trusted
            ? `Signing key ${keyId} matches the anchor clients verify against.`
            : `Signing key ${keyId} does NOT match the anchor clients verify against ` +
                `(${keyIdOf(anchor)}). Licences minted here would be rejected by every customer's ` +
                `CLI. Either restore the operator keypair to ${paths.dir}, or re-embed this ` +
                `public key and ship a release before taking payment.`,
    };
}
/** Both checks, and the list of reasons a payment must not be consumed. */
export function issuerReadiness() {
    const storage = checkIssuerStorage();
    const key = checkIssuerKey();
    const blockers = [];
    if (!storage.writable)
        blockers.push(storage.detail);
    if (!key.present || !key.trusted)
        blockers.push(key.detail);
    return { ok: blockers.length === 0, storage, key, blockers };
}
function parseEnvPrivateKey() {
    const raw = process.env.PROOFWORK_ISSUER_PRIVATE_KEY_PEM;
    if (!raw || raw.trim() === "") {
        return {
            ok: false,
            status: "absent",
            detail: `No key on disk and PROOFWORK_ISSUER_PRIVATE_KEY_PEM is not set. ` +
                `This deployment cannot mint a licence any customer could use.`,
        };
    }
    // Dashboards and shells mangle multi-line values in both directions: some
    // collapse the newlines to a literal backslash-n, some wrap the whole value in
    // quotes. Both produce a PEM that looks right in the UI and does not parse.
    const pem = raw
        .trim()
        .replace(/^["']|["']$/g, "")
        .replace(/\\n/g, "\n");
    try {
        const privateKey = crypto.createPrivateKey(pem);
        const publicKeyPem = crypto
            .createPublicKey(privateKey)
            .export({ type: "spki", format: "pem" })
            .toString();
        return { ok: true, pem, publicKeyPem };
    }
    catch (e) {
        return {
            ok: false,
            status: "invalid",
            detail: `PROOFWORK_ISSUER_PRIVATE_KEY_PEM is set but is not a usable private key ` +
                `(${e instanceof Error ? e.message : String(e)}). Nothing was written. Paste the ` +
                `whole file including both BEGIN and END lines.`,
        };
    }
}
function writeIssuerKeypair(pem, publicKeyPem) {
    const paths = issuerPaths();
    try {
        fs.mkdirSync(paths.dir, { recursive: true });
        // Both halves go down before anything reads them. A public file alone is
        // treated as unusable, which is correct but confusing in the health output.
        fs.writeFileSync(paths.privateKey, pem.endsWith("\n") ? pem : `${pem}\n`, "utf8");
        fs.writeFileSync(paths.publicKey, publicKeyPem, "utf8");
        try {
            fs.chmodSync(paths.privateKey, 0o600);
        }
        catch {
            // Windows ACLs differ, and the disk this targets is Linux. Not fatal.
        }
        return { ok: true };
    }
    catch (e) {
        return {
            ok: false,
            detail: `Could not write the issuer key to ${paths.dir}: ${e instanceof Error ? e.message : String(e)}`,
        };
    }
}
function envKeyMatchesAnchor(publicKeyPem) {
    const anchor = issuerPublicKey();
    return !!anchor && normalisePem(publicKeyPem) === normalisePem(anchor);
}
export function installIssuerKeyFromEnv() {
    const paths = issuerPaths();
    const existing = checkIssuerKey();
    if (existing.present && existing.trusted) {
        return {
            status: "already_present",
            detail: `Issuer key already on disk at ${paths.dir}; the environment was not consulted.`,
        };
    }
    const parsed = parseEnvPrivateKey();
    if (!parsed.ok) {
        if (existing.present) {
            return {
                status: "already_present",
                detail: `Untrusted issuer key is on disk at ${paths.dir} and the environment ` +
                    `did not supply a replacement that can be used. ${parsed.detail}`,
            };
        }
        return { status: parsed.status, detail: parsed.detail };
    }
    if (!envKeyMatchesAnchor(parsed.publicKeyPem)) {
        return {
            status: "invalid",
            detail: `PROOFWORK_ISSUER_PRIVATE_KEY_PEM does not match the public key compiled ` +
                `into the client (${keyIdOf(issuerPublicKey() ?? "")}). Nothing was written.`,
        };
    }
    const written = writeIssuerKeypair(parsed.pem, parsed.publicKeyPem);
    if (!written.ok) {
        return { status: "invalid", detail: written.detail };
    }
    if (existing.present) {
        return {
            status: "replaced",
            keyId: keyIdOf(parsed.publicKeyPem),
            detail: `Replaced the untrusted issuer key on disk at ${paths.dir} with the ` +
                `operator key from the environment.`,
        };
    }
    return {
        status: "installed",
        keyId: keyIdOf(parsed.publicKeyPem),
        detail: `Installed the issuer keypair from the environment into ${paths.dir}.`,
    };
}
/** The startup banner. Loud when unready, because the log is where an operator looks. */
export function renderReadiness(r) {
    const rule = "─".repeat(70);
    if (r.ok) {
        return (`  Issuer ready · key ${r.key.keyId} · ${r.storage.dir}\n` +
            `  The signing key matches the one compiled into every client, so a licence\n` +
            `  minted here will verify on a customer's machine.\n\n`);
    }
    return (`\n  ${rule}\n` +
        `  ISSUER NOT READY — payments will be refused, not silently mishandled.\n` +
        `  ${rule}\n\n` +
        r.blockers.map((b) => `  · ${b}\n`).join("\n") +
        `\n  The webhook returns 500 while this holds, so Stripe keeps retrying and\n` +
        `  the payment can still be honoured once it is fixed. Returning 200 would\n` +
        `  discard the delivery and the customer would have paid for nothing.\n\n`);
}
