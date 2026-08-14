import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadAccount } from "./account.js";
/**
 * Licensing.
 *
 * ## Why signed and offline rather than a server call
 *
 * The gate runs in CI, in pre-commit hooks, and on laptops behind corporate
 * proxies. A licence check that needs the network turns our outage into the
 * customer's blocked merge, and the first time that happens they remove us from
 * the pipeline and never come back. So a licence is a signed document the client
 * verifies locally: we sign once with a private key we hold, and every copy of
 * the CLI carries only the public half.
 *
 * The security property this gives us is narrow and worth stating plainly. It
 * means a customer cannot *forge* a licence — they would need our private key.
 * It does not mean a customer cannot *patch out* the check, because the code runs
 * on their machine. Nothing shipped to a client can prevent that, and vendors who
 * claim otherwise are selling obfuscation.
 *
 * That is acceptable because of where the real value sits. A patched client can
 * unlock its own findings. It still cannot produce a registry entry, because
 * registry entries are signed by the issuer, not the client. The thing customers
 * are actually buying — a claim a third party will believe — remains
 * unforgeable. We charge for the credential, and the credential is the part
 * cryptography can genuinely protect.
 *
 * ## Format
 *
 * `PW1.<base64url(payload)>.<base64url(signature)>`
 *
 * Self-contained and pasteable. Version-prefixed so a future format can be
 * rejected clearly instead of failing as a corrupt signature.
 */
const PREFIX = "PW1";
const b64url = (b) => b.toString("base64url");
const unb64url = (s) => Buffer.from(s, "base64url");
/**
 * Canonical JSON — sorted keys, no incidental whitespace.
 *
 * Signature verification compares bytes. If the bytes we sign and the bytes we
 * verify can differ for the same logical object, valid licences will fail at
 * random on a subset of machines and the failure will look like a forgery. Key
 * order is the usual culprit, so it is pinned here rather than left to V8.
 */
export function canonical(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonical).join(",")}]`;
    const entries = Object.entries(value)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
}
/* ------------------------------------------------------------- issuing --- */
/** Issue a licence. Runs on the issuer's machine only — needs the private key. */
export function issueLicense(payload, privateKeyPem) {
    const body = Buffer.from(canonical(payload), "utf8");
    const key = crypto.createPrivateKey(privateKeyPem);
    const sig = crypto.sign(null, body, key); // Ed25519 takes no digest algorithm
    return `${PREFIX}.${b64url(body)}.${b64url(sig)}`;
}
/** Generate an issuer keypair. The private half never leaves the issuer. */
export function generateIssuerKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    return {
        publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    };
}
/* ----------------------------------------------------------- verifying --- */
/**
 * The issuer's public key, compiled into every client.
 *
 * Overridable by env var for development and for a future key rotation. The
 * override is deliberately not a config-file setting: a licence check whose trust
 * anchor can be repointed by editing a file in the repo under test is not a
 * check, and `.proofwork.json` is exactly such a file.
 */
export function issuerPublicKey() {
    const fromEnv = process.env.PROOFWORK_ISSUER_PUBKEY;
    if (fromEnv && fromEnv.includes("BEGIN PUBLIC KEY"))
        return fromEnv;
    return EMBEDDED_ISSUER_PUBKEY || null;
}
/**
 * The issuer's public half, compiled into every client.
 *
 * Safe to publish — it can only *verify* a licence, never mint one. The private
 * half lives outside this repository entirely, in the issuer's home directory,
 * and nothing in the build reads it. That separation is the commercial model: a
 * customer who patches the client can unlock their own findings and still cannot
 * produce a credential anyone else will believe.
 *
 * Written by `proofwork license keys --embed`. It is a constant rather than a
 * file read at runtime on purpose — a trust anchor loaded from disk could be
 * swapped on the customer's machine, which would let anyone validate licences
 * they signed themselves.
 */
export const EMBEDDED_ISSUER_PUBKEY = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeMXOdZIzldUsMLX3+vJWHMIUgKynN/wXugGM6QU4rRk=\n-----END PUBLIC KEY-----\n";
export function verifyLicense(token, publicKeyPem) {
    const pub = publicKeyPem ?? issuerPublicKey();
    if (!pub) {
        return {
            valid: false,
            tier: "free",
            reason: "No issuer key available in this build — this is a development checkout.",
        };
    }
    const parts = token.trim().split(".");
    if (parts.length !== 3 || parts[0] !== PREFIX) {
        return {
            valid: false,
            tier: "free",
            reason: `Not a Proofwork licence key. Expected a key beginning "${PREFIX}." — check for a truncated paste.`,
        };
    }
    let payload;
    let body;
    try {
        body = unb64url(parts[1]);
        payload = JSON.parse(body.toString("utf8"));
    }
    catch {
        return { valid: false, tier: "free", reason: "Licence body is corrupt — request a re-issue." };
    }
    let signatureOk = false;
    try {
        signatureOk = crypto.verify(null, body, crypto.createPublicKey(pub), unb64url(parts[2]));
    }
    catch {
        signatureOk = false;
    }
    if (!signatureOk) {
        return {
            valid: false,
            tier: "free",
            reason: "Licence signature does not verify — this key was not issued by Proofwork.",
        };
    }
    // Signature first, contents second. Reading fields off an unverified payload —
    // even to produce a friendlier error — is how signature checks get bypassed.
    const now = Date.now();
    if (Number.isNaN(Date.parse(payload.expires_at))) {
        return { valid: false, tier: "free", reason: "Licence has no readable expiry date." };
    }
    if (Date.parse(payload.expires_at) < now) {
        return {
            valid: false,
            tier: "free",
            payload,
            reason: `Licence expired on ${payload.expires_at.slice(0, 10)} — renew to keep issuing certificates.`,
        };
    }
    if (payload.tier !== "certified" && payload.tier !== "assured") {
        return { valid: false, tier: "free", reason: `Unknown tier "${payload.tier}" in licence.` };
    }
    return { valid: true, tier: payload.tier, payload };
}
/** Does this licence cover this repository? */
export function licenseCoversRepo(payload, repoName) {
    return payload.repos.some((r) => r === "*" || r.toLowerCase() === repoName.toLowerCase());
}
/* ------------------------------------------------------------- storage --- */
/**
 * Licences live in the user's home directory, never in the repository.
 *
 * Two reasons, both learned the expensive way by other people: a licence key
 * committed to a repo is a licence key on GitHub, and a licence stored inside the
 * tree under test would be visible to the very agent whose work we are grading.
 */
export function licensePath() {
    return process.env.PROOFWORK_LICENSE_PATH ?? path.join(os.homedir(), ".proofwork", "license");
}
export function storeLicense(token) {
    const p = licensePath();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `${token.trim()}\n`, "utf8");
    try {
        fs.chmodSync(p, 0o600);
    }
    catch {
        /* Windows ACLs differ; the file is still outside the repo, which is the point. */
    }
    return p;
}
export function loadLicense() {
    const fromEnv = process.env.PROOFWORK_LICENSE;
    if (fromEnv?.trim())
        return fromEnv.trim();
    const p = licensePath();
    if (!fs.existsSync(p))
        return null;
    const raw = fs.readFileSync(p, "utf8").trim();
    return raw || null;
}
/** The tier this machine is entitled to right now. Free when anything is wrong. */
/**
 * Two organisation names, compared the way a person would.
 *
 * Case and spacing vary between what someone types at signup and what was typed
 * on the licence. Nothing beyond that is normalised — no stripping of "Inc" or
 * "Ltd" — because two companies with similar names are two companies, and a
 * matcher that guesses would hand one of them the other's entitlement.
 */
function sameOrganisation(a, b) {
    const norm = (s) => s.trim().toLowerCase().replace(/\s+/g, " ").replace(/[.,]+$/, "");
    return norm(a) === norm(b) && norm(a) !== "";
}
/**
 * What this machine is entitled to, for the account currently signed in.
 *
 * ## The bug this closes
 *
 * A licence lives on the machine; an account is who is signed into it. Those are
 * different things, and treating the licence alone as the answer meant a machine
 * that had ever held one reported its tier to whoever came next. Signing up a new
 * organisation and immediately seeing "Tier assured" — on someone else's licence
 * — is a confusing first run for a self-serve customer and an untrue statement
 * about who is entitled to what.
 *
 * A licence now applies when it was issued to the organisation signed in.
 *
 * ## Why a missing account still honours the licence
 *
 * CI runners and the issuer's own machine have no account, and requiring one
 * would break every automated install for no safety gain — the licence key is
 * itself the credential there, supplied deliberately per run. The check is about
 * *disambiguating* between accounts on one machine, not about adding a second
 * factor.
 */
export function currentEntitlement() {
    const token = loadLicense();
    if (!token) {
        return { valid: false, tier: "free", reason: "No licence installed — running the free gate." };
    }
    const verdict = verifyLicense(token);
    if (!verdict.valid || !verdict.payload)
        return verdict;
    const account = loadAccount();
    // No account, or one with no organisation to compare: the licence stands on
    // its own. This is the CI and issuer path.
    if (!account?.organisation)
        return verdict;
    if (!sameOrganisation(account.organisation, verdict.payload.subject)) {
        return {
            valid: false,
            tier: "free",
            // Carried so a support conversation can see which licence is installed
            // without asking anyone to read a token out of a file.
            payload: verdict.payload,
            reason: `This machine holds a licence issued to "${verdict.payload.subject}", but you are ` +
                `signed in as "${account.organisation}". Running the free gate rather than lending ` +
                `one organisation's entitlement to another. Activate the licence for ` +
                `"${account.organisation}", or sign in as the organisation the licence names.`,
        };
    }
    return verdict;
}
