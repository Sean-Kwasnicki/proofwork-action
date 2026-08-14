import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
/**
 * Accounts.
 *
 * ## Why everyone signs up, including free users
 *
 * The free tier exists to produce two things: a prospect who has felt the
 * product work, and a way to reach them. Anonymous free usage produces only the
 * first, and a funnel you cannot contact is a cost centre.
 *
 * So signup is the price of the free tier. It is a low price — an email address —
 * and it is charged before the first verdict rather than after, because a verdict
 * already delivered is a reason to close the terminal.
 *
 * ## What this is and is not
 *
 * This is the **account model**, not authentication. Records live in the user's
 * home directory and nothing here verifies that the person typing an address
 * owns it. That is honest for a CLI: there is no server to authenticate against,
 * and a local file cannot be a source of truth about identity.
 *
 * What it does give is the shape the hosted version needs — the same fields, the
 * same identifiers, the same entitlement resolution — so moving to a real service
 * is a change of storage rather than a redesign. When that service exists,
 * `signup` posts to it, the API returns a signed token, and everything downstream
 * of this file stays as it is.
 *
 * Stated plainly so nobody mistakes it for security: **a local account file is a
 * record of intent, not proof of identity.** Anything that must not be forged —
 * a certificate, a registry record — is signed by the issuer and does not consult
 * this file at all.
 */
const ACCOUNT_DIR = () => process.env.PROOFWORK_ACCOUNT_DIR ?? path.join(os.homedir(), ".proofwork");
const ACCOUNT_PATH = () => path.join(ACCOUNT_DIR(), "account.json");
/** Issuer-side list of everyone who has signed up. The sales list. */
const SIGNUP_LOG = () => process.env.PROOFWORK_SIGNUP_LOG ??
    path.join(process.env.PROOFWORK_ISSUER_DIR ?? path.join(os.homedir(), ".proofwork-issuer"), "signups.jsonl");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
/**
 * Validate an address before recording it.
 *
 * A sales list full of typos is worse than a shorter clean one: every bounce
 * costs sender reputation, and reputation is shared across every later send.
 * Rejecting `foo@bar` here is cheaper than discovering it in a campaign.
 */
export function isPlausibleEmail(value) {
    return EMAIL_RE.test(value.trim()) && value.trim().length <= 254;
}
export function accountIdFor(email) {
    return `acc_${crypto.createHash("sha256").update(email.trim().toLowerCase()).digest("hex").slice(0, 16)}`;
}
/**
 * Create or return the local account.
 *
 * Idempotent by address. Signing up twice with the same email returns the
 * existing account rather than creating a duplicate — the alternative is a sales
 * list where one person appears four times because they reinstalled.
 */
export function signUp(input) {
    const email = input.email.trim().toLowerCase();
    if (!isPlausibleEmail(email)) {
        throw new Error(`"${input.email}" does not look like an email address. It is the only thing the free tier costs, ` +
            `and a bad address means we cannot send you the certificate you earn.`);
    }
    /**
     * The organisation is required, not optional.
     *
     * It is the name printed on every certificate, badge, and registry record. A
     * credential reading "billing-sync" instead of "Harborline Freight" tells a
     * buyer nothing about who is making the claim, and the name cannot be corrected
     * afterwards — records are signed, so a wrong name means re-issuing every
     * credential that carries it.
     *
     * Collecting it at signup, before anything is issued, is the only point at
     * which fixing it is free.
     */
    const organisation = (input.organisation ?? "").trim();
    if (organisation.length < 2) {
        throw new Error("An organisation name is required. It is printed on every certificate and signed into every " +
            "record, and because records cannot be edited afterwards, a wrong name means re-issuing all " +
            "of them.\n\n  proofwork signup --email you@company.com --org \"Your Company Ltd\"");
    }
    const existing = loadAccount();
    if (existing && existing.email === email) {
        return { account: existing, created: false, accountPath: ACCOUNT_PATH() };
    }
    const account = {
        account_id: accountIdFor(email),
        email,
        ...(input.name ? { name: input.name } : {}),
        ...(input.organisation ? { organisation: input.organisation } : {}),
        created_at: new Date().toISOString(),
        tier: "free",
        // No server means no confirmation link, and claiming otherwise would be a
        // false statement about consent on the one record used for outreach.
        email_verified: false,
    };
    fs.mkdirSync(ACCOUNT_DIR(), { recursive: true });
    fs.writeFileSync(ACCOUNT_PATH(), `${JSON.stringify(account, null, 2)}\n`, "utf8");
    // Issuer-side capture. Separate from the customer's own copy so a customer
    // deleting their file does not erase our record of the signup.
    try {
        const log = SIGNUP_LOG();
        fs.mkdirSync(path.dirname(log), { recursive: true });
        fs.appendFileSync(log, `${JSON.stringify(account)}\n`, "utf8");
    }
    catch {
        // Failing to record a signup must not block someone from using the product.
    }
    return { account, created: true, accountPath: ACCOUNT_PATH() };
}
export function loadAccount() {
    try {
        const p = ACCOUNT_PATH();
        if (!fs.existsSync(p))
            return null;
        return JSON.parse(fs.readFileSync(p, "utf8"));
    }
    catch {
        return null;
    }
}
export function signOut() {
    const p = ACCOUNT_PATH();
    if (!fs.existsSync(p))
        return false;
    fs.unlinkSync(p);
    return true;
}
/** Issuer-side: everyone who has signed up. */
export function allSignups() {
    try {
        return fs
            .readFileSync(SIGNUP_LOG(), "utf8")
            .split(/\r?\n/)
            .filter(Boolean)
            .map((l) => JSON.parse(l));
    }
    catch {
        return [];
    }
}
/** Rendered for someone who just signed up. */
export function renderSignup(r) {
    // `null` marks a line to drop; "" is a deliberate blank. Filtering on `""`
    // collapsed every spacer and ran the whole block together.
    const lines = [
        "",
        // "Signed in" overstated what happened. Nothing verified that this person
        // owns this address, because there is no server to verify against — an
        // external review called it theatre and was right. A product that sells
        // verification cannot ship a login that only resembles one.
        r.created ? "  Local profile created." : "  Local profile already exists.",
        "",
        `    Account  ${r.account.account_id}`,
        `    Email    ${r.account.email}`,
        r.account.organisation ? `    Org      ${r.account.organisation}` : null,
        `    Tier     ${r.account.tier}`,
        `    Email    unverified — this profile is stored on this machine only`,
        "",
        "  The free tier runs the foundational gate and returns a verdict.",
        "  It does not show which check failed, and nothing it produces is",
        "  written to the registry.",
        "",
        "  Next:  proofwork report",
        "",
    ];
    return `${lines.filter((l) => l !== null).join("\n")}\n`;
}
