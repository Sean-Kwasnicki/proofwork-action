import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { generateIssuerKeypair, issueLicense } from "./license.js";
/**
 * Issuer-side operations — minting licences.
 *
 * ## Why this is separate from everything else
 *
 * Every other module in this project runs on a customer's machine. This one runs
 * only on ours, because it needs the private key, and the entire commercial model
 * rests on that key never being anywhere else. A customer with a patched client
 * can unlock their own findings; a customer with this key can mint credentials
 * indistinguishable from ours, and there is no recovering from that.
 *
 * The separation is therefore physical rather than a matter of discipline: the
 * private key is written outside the repository, to the operator's home
 * directory, and nothing in the build reads it.
 *
 * ## The gap this closes
 *
 * The licence *verifier* shipped without an issuer, which meant no licence could
 * exist. `EMBEDDED_ISSUER_PUBKEY` was an empty string, so every key failed to
 * validate, every run fell back to the free tier, and the paid product was
 * unreachable — a payment path with nothing on the other side of it. A checkout
 * that takes money and delivers a free-tier experience is worse than no checkout.
 */
const ISSUER_DIR = () => process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer");
const PRIVATE_KEY_PATH = () => path.join(ISSUER_DIR(), "issuer-private.pem");
const PUBLIC_KEY_PATH = () => path.join(ISSUER_DIR(), "issuer-public.pem");
const ISSUED_LOG = () => path.join(ISSUER_DIR(), "issued.jsonl");
const keyIdOf = (pub) => crypto.createHash("sha256").update(pub.replace(/\s+/g, "")).digest("hex").slice(0, 16);
/**
 * Load the issuer keypair, creating it once if absent.
 *
 * Rotation is deliberately not automatic. Replacing the key invalidates every
 * licence and every registry record ever signed with the old one, so it has to be
 * a decision someone makes on purpose, not something a stray command does.
 */
export function loadOrCreateIssuerKeys() {
    const dir = ISSUER_DIR();
    fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(PRIVATE_KEY_PATH()) && fs.existsSync(PUBLIC_KEY_PATH())) {
        const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH(), "utf8");
        return {
            publicKeyPem,
            privateKeyPem: fs.readFileSync(PRIVATE_KEY_PATH(), "utf8"),
            keyId: keyIdOf(publicKeyPem),
            created: false,
        };
    }
    const { publicKeyPem, privateKeyPem } = generateIssuerKeypair();
    fs.writeFileSync(PRIVATE_KEY_PATH(), privateKeyPem, "utf8");
    fs.writeFileSync(PUBLIC_KEY_PATH(), publicKeyPem, "utf8");
    try {
        fs.chmodSync(PRIVATE_KEY_PATH(), 0o600);
    }
    catch {
        // Windows ACLs differ. The file is outside the repository, which is the part
        // that matters — a key inside the tree is one `git add` from being public.
    }
    return { publicKeyPem, privateKeyPem, keyId: keyIdOf(publicKeyPem), created: true };
}
/**
 * Mint a licence and record that it was minted.
 *
 * The log is append-only and local. It is not the registry — it answers "what
 * have we sold?", which is a question about us, whereas the registry answers
 * "did this customer pass?", which is a question about them. Keeping the two
 * apart means a support lookup never touches the evidence customers rely on.
 */
export function issueLicenseFor(req) {
    const keys = loadOrCreateIssuerKeys();
    const now = new Date();
    const payload = {
        jti: `lic_${crypto.randomBytes(8).toString("hex")}`,
        subject: req.subject,
        tier: req.tier,
        issued_at: now.toISOString(),
        // An exact expiry wins over a day count. A subscription ends when the paid
        // period ends, and that is a timestamp from Stripe rather than a duration.
        expires_at: req.expiresAt ?? new Date(now.getTime() + req.days * 86_400_000).toISOString(),
        repos: req.repos.length ? req.repos : ["*"],
        ...(req.plan ? { plan: req.plan } : {}),
    };
    const token = issueLicense(payload, keys.privateKeyPem);
    try {
        fs.appendFileSync(ISSUED_LOG(), `${JSON.stringify({ ...payload, key_id: keys.keyId, at: now.toISOString() })}\n`, "utf8");
    }
    catch {
        // A failure to log must not prevent a customer receiving what they paid for.
        // The licence itself is self-describing, so the record can be reconstructed.
    }
    return { token, payload, keyId: keys.keyId };
}
/** Where the private key lives, for an operator who needs to back it up. */
export function issuerPaths() {
    return {
        dir: ISSUER_DIR(),
        privateKey: PRIVATE_KEY_PATH(),
        publicKey: PUBLIC_KEY_PATH(),
        log: ISSUED_LOG(),
    };
}
/**
 * Rewrite the embedded public key in the source tree.
 *
 * Shipping the public half is what makes offline verification possible. This
 * edits the constant rather than reading a file at runtime, deliberately: a trust
 * anchor loaded from disk can be replaced on the customer's machine, which would
 * let anyone mint their own licences by swapping the key the client trusts.
 */
export function embedPublicKey(repoRoot, publicKeyPem) {
    const file = path.join(repoRoot, "src", "license.ts");
    const src = fs.readFileSync(file, "utf8");
    const escaped = publicKeyPem.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const next = src.replace(/export const EMBEDDED_ISSUER_PUBKEY = "[^"]*";/, `export const EMBEDDED_ISSUER_PUBKEY = "${escaped}";`);
    if (next === src)
        return { file, changed: false };
    fs.writeFileSync(file, next, "utf8");
    return { file, changed: true };
}
