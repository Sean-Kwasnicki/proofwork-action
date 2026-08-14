import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SpendGuard, } from "./spendGuard.js";
/**
 * The static gate and the runtime guard, joined.
 *
 * ## Why they have to be one product
 *
 * The gate reads code and can prove a boundary was *declared*. It cannot prove
 * every path honours it — that is not statically decidable, and this project has
 * said so consistently rather than pretending otherwise.
 *
 * The guard enforces at the moment money moves and knows nothing about whether a
 * boundary was declared anywhere.
 *
 * Sold separately, each carries the other's weakness as a disclaimer. Joined,
 * they close it: the gate confirms a policy exists and is consulted, the guard
 * confirms it was obeyed, and this module produces the record that ties the two
 * together. Only then can "this agent's spending is bounded" be said without a
 * footnote.
 *
 * ## What this file adds that `SpendGuard` does not
 *
 * `SpendGuard` decides and records in memory. That is correct for a library and
 * insufficient as evidence: a hash chain that vanishes when the process exits
 * proves nothing to anyone who was not watching.
 *
 * Here the chain is appended to disk as it grows, under the same account that
 * holds the vault, so a run's enforcement history survives the run. The static
 * gate can then be asked whether the policy the guard enforced is the policy the
 * repository declares — the question neither layer can answer alone.
 */
const GUARD_LOG = () => process.env.PROOFWORK_GUARD_LOG ??
    path.join(process.env.PROOFWORK_ACCOUNT_DIR ?? path.join(os.homedir(), ".proofwork"), "guard.jsonl");
/**
 * A guard whose decisions outlive the process.
 *
 * Wraps rather than replaces `SpendGuard`: every decision rule stays in one
 * place, and this layer only concerns itself with durability. Splitting them the
 * other way — reimplementing the rules here with persistence built in — would
 * give two implementations that drift, and the one enforcing money would be the
 * one nobody tested.
 */
export class AttestedSpendGuard {
    guard;
    logPath;
    constructor(policy, opts = {}) {
        this.guard = new SpendGuard(policy);
        this.logPath = opts.logPath ?? GUARD_LOG();
    }
    get sessionTotalMinor() {
        return this.guard.sessionTotalMinor;
    }
    get ledger() {
        return this.guard.ledger;
    }
    verify() {
        return this.guard.verify();
    }
    async spend(req, execute) {
        const outcome = await this.guard.spend(req, execute);
        let persistedTo = null;
        try {
            fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
            fs.appendFileSync(this.logPath, `${JSON.stringify(outcome.record)}\n`, "utf8");
            persistedTo = this.logPath;
        }
        catch {
            // Persistence failing must not change the decision. A guard that let a
            // payment through because it could not write a log would have inverted its
            // own purpose; a guard that blocked one for the same reason would take an
            // outage in the logging path and turn it into an outage in billing.
        }
        return { ...outcome, persistedTo };
    }
}
/** Everything the guard has decided, across every run. */
export function readEnforcementLog(logPath = GUARD_LOG()) {
    try {
        return fs
            .readFileSync(logPath, "utf8")
            .split(/\r?\n/)
            .filter(Boolean)
            .map((l) => JSON.parse(l));
    }
    catch {
        return [];
    }
}
/**
 * Summarise enforcement, re-checking the chain rather than trusting it.
 *
 * The same discipline the vault uses: a stored "verified" flag would keep
 * reporting intact after somebody edited the file. Recomputing on read is the
 * only version that means anything.
 */
export function summariseEnforcement(records) {
    const allowed = records.filter((r) => r.decision === "allowed");
    const blocked = records.filter((r) => r.decision !== "allowed");
    const byDecision = new Map();
    for (const r of blocked)
        byDecision.set(r.decision, (byDecision.get(r.decision) ?? 0) + 1);
    let expected = "genesis";
    let chainIntact = true;
    for (const r of records) {
        if (r.prevHash !== expected) {
            chainIntact = false;
            break;
        }
        expected = r.hash;
    }
    return {
        attempts: records.length,
        allowed: allowed.length,
        blocked: blocked.length,
        totalAllowedMinor: allowed.reduce((s, r) => s + r.amountMinor, 0),
        totalBlockedMinor: blocked.reduce((s, r) => s + r.amountMinor, 0),
        blockedBy: [...byDecision.entries()]
            .map(([decision, count]) => ({ decision, count }))
            .sort((a, b) => b.count - a.count),
        chainIntact: records.length === 0 ? true : chainIntact,
        firstAt: records[0]?.at ?? null,
        lastAt: records[records.length - 1]?.at ?? null,
    };
}
const money = (m) => `$${(m / 100).toFixed(2)}`;
/** Rendered for an operator asking what the guard actually did. */
export function renderEnforcement(s) {
    const rule = "─".repeat(70);
    if (s.attempts === 0) {
        return [
            "",
            "  RUNTIME ENFORCEMENT",
            `  ${rule}`,
            "",
            "  No payment attempts recorded.",
            "",
            "  The static gate can confirm a spend policy is declared and consulted.",
            "  Only the guard can confirm it was obeyed — route payments through",
            "  AttestedSpendGuard and this fills in.",
            "",
        ].join("\n");
    }
    return [
        "",
        "  RUNTIME ENFORCEMENT",
        `  ${rule}`,
        "",
        `  ${s.attempts} attempt(s) · ${s.allowed} allowed · ${s.blocked} blocked`,
        `  allowed ${money(s.totalAllowedMinor)} · refused ${money(s.totalBlockedMinor)}`,
        "",
        ...(s.blockedBy.length
            ? ["  Refusals by reason:", ...s.blockedBy.map((b) => `    ${String(b.count).padStart(3)}  ${b.decision}`), ""]
            : []),
        `  Chain: ${s.chainIntact ? "intact" : "BROKEN — a record was altered or removed"}`,
        s.firstAt ? `  Covering ${s.firstAt.slice(0, 10)} to ${(s.lastAt ?? "").slice(0, 10)}` : "",
        "",
        "  Refused attempts are recorded alongside allowed ones. A log of only what",
        "  was permitted would omit the moment the agent tried to exceed its authority,",
        "  which is the entry an investigator opens first.",
        "",
    ]
        .filter((l, i, arr) => !(l === "" && arr[i - 1] === ""))
        .join("\n");
}
