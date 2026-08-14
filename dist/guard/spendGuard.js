import crypto from "node:crypto";
/** Operations that move money away from the operator. */
export const OUTBOUND = ["refund", "payout", "transfer"];
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
/**
 * A session's worth of guarded spending.
 *
 * Records every attempt, not only the successful ones. A refused attempt is the
 * most interesting entry in the log — it is the moment the agent tried to exceed
 * its authority — and a guard that only recorded what it permitted would erase
 * exactly the evidence an investigator needs.
 */
export class SpendGuard {
    policy;
    records = [];
    total = 0;
    constructor(policy) {
        this.policy = policy;
    }
    get sessionTotalMinor() {
        return this.total;
    }
    get ledger() {
        return this.records;
    }
    /** Decide, without executing. Exposed so a caller can preflight. */
    evaluate(req) {
        if (!this.policy) {
            return {
                decision: "blocked_no_policy",
                reason: "No spend policy is in force, so nothing may be spent. Declare a ceiling and an approval " +
                    "path before this agent is allowed to move money. Refusing is deliberate — an absent " +
                    "policy is not permission.",
            };
        }
        if (req.currency.toLowerCase() !== this.policy.currency.toLowerCase()) {
            return {
                decision: "blocked_no_policy",
                reason: `Policy governs ${this.policy.currency.toUpperCase()} but this request is in ` +
                    `${req.currency.toUpperCase()}. A ceiling in one currency says nothing about an amount in ` +
                    `another, so this is refused rather than converted.`,
            };
        }
        const approved = Boolean(req.approval?.token);
        const op = req.operation ?? "charge";
        /**
         * Objective first, amount second.
         *
         * The ordering is the point. An agent doing something outside its purpose is
         * a different problem from an agent doing its job too expensively, and
         * checking the amount first would let a refund from a billing agent pass
         * simply for being small. Category before magnitude.
         */
        if (this.policy.allowedOperations && !this.policy.allowedOperations.includes(op)) {
            return {
                decision: "blocked_off_objective",
                reason: `This agent is declared for ${this.policy.allowedOperations.join(", ")} — a ${op} is ` +
                    `outside what it exists to do. Acting outside a declared purpose needs a human whatever ` +
                    `the amount, because the size of an off-objective action says nothing about whether it ` +
                    `was intended.`,
            };
        }
        /**
         * Destination next.
         *
         * The right amount, in the right operation, to the wrong party passes every
         * amount-based rule ever written. It is the version of this attack that
         * survives review, so it is checked before anything numeric.
         */
        if (this.policy.allowedRecipients && req.recipient !== undefined) {
            const permitted = this.policy.allowedRecipients.some((r) => typeof r === "string" ? r.toLowerCase() === req.recipient.toLowerCase() : r.test(req.recipient));
            if (!permitted) {
                return {
                    decision: "blocked_unknown_recipient",
                    reason: `"${req.recipient}" is not a declared destination for this agent. The amount and the ` +
                        `operation may both be correct — money reaching a party nobody approved is the failure ` +
                        `here, and it is the one that looks normal in every report.`,
                };
            }
        }
        // A declared destination list that the caller ignores is not a control. An
        // unspecified recipient is treated as unknown rather than as permitted.
        if (this.policy.allowedRecipients && req.recipient === undefined && OUTBOUND.includes(op)) {
            return {
                decision: "blocked_unknown_recipient",
                reason: `This policy declares permitted destinations, but this ${op} names no recipient. An ` +
                    `outbound movement with no stated destination cannot be checked against the list, so it ` +
                    `is refused rather than assumed.`,
            };
        }
        if (this.policy.requireApprovalFor?.includes(op) && !approved) {
            return {
                decision: "blocked_needs_approval",
                reason: `This policy requires human approval for every ${op}, regardless of amount.`,
            };
        }
        // A per-operation ceiling overrides the general one, so "bill freely, refund
        // never without asking" is expressible — the shape most deployments want.
        const opCeiling = this.policy.perOperationMaxMinor?.[op];
        if (opCeiling !== undefined && req.amountMinor > opCeiling && !approved) {
            return {
                decision: "blocked_needs_approval",
                reason: `${fmt(req.amountMinor, req.currency)} exceeds the ${op} ceiling of ` +
                    `${fmt(opCeiling, this.policy.currency)}.`,
            };
        }
        if (this.policy.alwaysRequireApproval && !approved) {
            return {
                decision: "blocked_needs_approval",
                reason: "This policy requires human approval for every payment, regardless of amount.",
            };
        }
        if (req.amountMinor > this.policy.maxAmountMinor && !approved) {
            return {
                decision: "blocked_needs_approval",
                reason: `${fmt(req.amountMinor, req.currency)} exceeds the ceiling of ` +
                    `${fmt(this.policy.maxAmountMinor, this.policy.currency)}. The agent may spend below that ` +
                    `line on its own; above it a human has to say yes.`,
            };
        }
        const daily = this.policy.dailyLimitMinor;
        if (daily !== undefined && this.total + req.amountMinor > daily) {
            return {
                decision: "blocked_over_ceiling",
                reason: `This would take session spending to ${fmt(this.total + req.amountMinor, req.currency)}, ` +
                    `past the limit of ${fmt(daily, this.policy.currency)}. Approval does not lift a cumulative ` +
                    `cap — that is what makes it a cap rather than a prompt.`,
            };
        }
        return {
            decision: "allowed",
            reason: approved
                ? `Approved by ${req.approval?.approvedBy ?? "a human"}.`
                : `Within the declared ceiling of ${fmt(this.policy.maxAmountMinor, this.policy.currency)}.`,
        };
    }
    /**
     * Run a payment through the guard.
     *
     * `execute` is only invoked when the decision is `allowed`. That ordering is
     * the whole point: a guard that executed first and judged afterwards would be
     * an audit log, and an audit log does not stop anything.
     */
    async spend(req, execute) {
        const { decision, reason } = this.evaluate(req);
        const allowed = decision === "allowed";
        let result;
        if (allowed) {
            result = await execute();
            this.total += req.amountMinor;
        }
        const record = this.append({
            at: new Date().toISOString(),
            amountMinor: req.amountMinor,
            currency: req.currency,
            purpose: req.reason,
            operation: req.operation ?? "charge",
            recipient: req.recipient ?? null,
            decision,
            approvedBy: req.approval?.approvedBy ?? null,
            sessionTotalMinor: this.total,
        });
        return {
            decision,
            allowed,
            reason,
            ...(result !== undefined ? { result } : {}),
            record,
        };
    }
    append(base) {
        const prevHash = this.records[this.records.length - 1]?.hash ?? "genesis";
        const hash = sha256(JSON.stringify({ ...base, prevHash }));
        const record = { ...base, prevHash, hash };
        this.records.push(record);
        return record;
    }
    /** Does the chain still hold? Detects an entry edited or removed after the fact. */
    verify() {
        const errors = [];
        let expected = "genesis";
        for (const r of this.records) {
            if (r.prevHash !== expected) {
                errors.push(`Chain broken at ${r.at} — an earlier record was altered or removed.`);
            }
            const { hash, ...rest } = r;
            if (sha256(JSON.stringify(rest)) !== hash) {
                errors.push(`Record at ${r.at} does not match its hash — it was edited after being written.`);
            }
            expected = r.hash;
        }
        return { ok: errors.length === 0, errors };
    }
}
function fmt(minor, currency) {
    return `${(minor / 100).toFixed(2)} ${currency.toUpperCase()}`;
}
/** Rendered for an operator reviewing what an agent tried to do. */
export function renderSpendLedger(guard) {
    const rows = guard.ledger.map((r) => {
        const mark = r.decision === "allowed" ? "ALLOWED" : "BLOCKED";
        const dir = OUTBOUND.includes(r.operation) ? "OUT" : "in ";
        const to = r.recipient ? ` -> ${r.recipient}` : "";
        return `  ${mark.padEnd(8)} ${dir} ${r.operation.padEnd(9)} ${fmt(r.amountMinor, r.currency).padStart(11)}  ${r.purpose}${to}`;
    });
    const v = guard.verify();
    return [
        "",
        "  SPEND LEDGER",
        `  ${"─".repeat(62)}`,
        ...(rows.length ? rows : ["  (no payment attempts)"]),
        `  ${"─".repeat(62)}`,
        `  Total actually charged: ${fmt(guard.sessionTotalMinor, "usd")}`,
        `  Chain: ${v.ok ? "intact" : `BROKEN — ${v.errors[0]}`}`,
        "",
    ].join("\n");
}
