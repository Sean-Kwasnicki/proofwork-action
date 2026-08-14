import fs from "node:fs";
import path from "node:path";
import { findAgentFiles } from "./agentSecurity.js";
/**
 * Agent autonomy — can this agent act against its owner without being asked?
 *
 * `agentSecurity` asks what an attacker could steal from the agent's context.
 * This asks a different and blunter question: what can the agent do *on its own*,
 * and did anybody agree to that?
 *
 * The failure that actually costs people money is not exotic. An agent is granted
 * a capability that moves money, deletes data, or speaks to the outside world as
 * its owner — and separately, somewhere in a config file, approval prompts were
 * switched off so the agent would stop interrupting. Neither decision looks
 * dangerous alone. Together they mean the first mistaken tool call is also the
 * final one, with no human in the loop to catch it.
 *
 * Both halves are declared in configuration, so both are statically detectable.
 * That is the whole check: high-consequence capability, plus a bypassed gate,
 * equals an agent that can act irreversibly without consent.
 *
 * Evidences EU AI Act Art. 14 (human oversight) and NIST AI RMF MANAGE 2.4
 * (mechanisms to supersede, disengage, or deactivate).
 *
 * Scope: what the configuration permits, not what the agent has done. Observing
 * live behaviour needs a running agent and the owner's authorization.
 */
const FRAMEWORK_REFS = {
    iso42001: ["A.9.2 Processes for Responsible Use of AI Systems", "A.6.2.5 AI-System Deployment"],
    nist: ["MANAGE 2.4", "MAP 2.2"],
    eu: ["Art. 14 Human Oversight"],
};
const MAX_BYTES = 512 * 1024;
/**
 * Capabilities whose first wrong call cannot be undone. Deliberately not a list of
 * "risky-sounding" words: each entry names something that moves money, destroys
 * state, or speaks as the owner to a third party.
 */
const CAPABILITY_RULES = [
    // money movement
    { id: "stripe", re: /\bstripe\b/i, consequence: "money", what: "Stripe (payments)" },
    { id: "paypal", re: /\bpaypal\b/i, consequence: "money", what: "PayPal (payments)" },
    { id: "coinbase", re: /\bcoinbase\b/i, consequence: "money", what: "Coinbase (crypto)" },
    { id: "wallet", re: /\b(?:wallet|web3|ethers|solana|x402)\b/i, consequence: "money", what: "crypto wallet / on-chain payment" },
    { id: "payment_generic", re: /\b(?:payment|checkout|billing|invoice|payout|charge_card)s?\b/i, consequence: "money", what: "payment capability" },
    // irreversible state change
    { id: "shell", re: /"(?:command|cmd)"\s*:\s*"(?:bash|sh|zsh|cmd|powershell|pwsh)"/i, consequence: "destructive", what: "unrestricted shell" },
    { id: "rm_rf", re: /rm\s+-[rf]{1,2}\b|Remove-Item[^\n]*-Recurse/i, consequence: "destructive", what: "recursive delete" },
    { id: "sql_drop", re: /\b(?:DROP\s+(?:TABLE|DATABASE)|TRUNCATE\s+TABLE)\b/i, consequence: "destructive", what: "destructive SQL" },
    { id: "force_push", re: /git\s+push[^\n]*--force|push\s+-f\b/i, consequence: "destructive", what: "force push" },
    // speaking as the owner
    { id: "email", re: /\b(?:sendgrid|mailgun|postmark|smtp|send_email|nodemailer)\b/i, consequence: "impersonation", what: "outbound email" },
    { id: "sms", re: /\b(?:twilio|vonage|send_sms)\b/i, consequence: "impersonation", what: "outbound SMS" },
    { id: "chat", re: /\b(?:slack|discord)[-_]?(?:webhook|post|send)\b|chat\.postMessage/i, consequence: "impersonation", what: "posting as the owner" },
];
/**
 * Settings that remove the human from the loop. Each of these exists for a good
 * reason during development; each becomes the difference between a near-miss and
 * an incident once a consequential tool is attached.
 */
const BYPASS_RULES = [
    // Keys are matched with optional quoting: JSON5, YAML, and hand-edited config
    // all appear in the wild, and requiring double quotes let `autoApprove : true`
    // through untouched.
    { id: "auto_approve", re: /["']?autoApprove["']?\s*[:=]\s*(?:true|\[)/i, what: "autoApprove enabled" },
    { id: "always_allow", re: /["']?alwaysAllow["']?\s*[:=]\s*(?:true|\[)/i, what: "alwaysAllow enabled" },
    { id: "skip_permissions", re: /--dangerously-skip-permissions|dangerouslySkipPermissions/i, what: "permission prompts skipped" },
    { id: "yolo", re: /\byolo\s*(?:mode)?\s*[:=]\s*true|--yolo\b/i, what: "yolo mode" },
    { id: "auto_confirm", re: /"(?:autoConfirm|confirm)"\s*:\s*false|--no-confirm\b|--assume-yes\b|\s-y\b/i, what: "confirmation disabled" },
    { id: "permission_allow_all", re: /"permission(?:_policy|Policy)?"\s*:\s*"(?:always_allow|allow|none)"/i, what: "permission policy set to allow-all" },
];
/** Scan one agent config/prompt file for consequential capability and bypassed gates. */
export function scanForAutonomyRisks(rel, text) {
    const findings = [];
    text.split(/\r?\n/).forEach((line, idx) => {
        for (const rule of CAPABILITY_RULES) {
            if (rule.re.test(line)) {
                findings.push({
                    file: rel, line: idx + 1, kind: "capability",
                    id: rule.id, what: rule.what, consequence: rule.consequence,
                });
                break;
            }
        }
        for (const rule of BYPASS_RULES) {
            if (rule.re.test(line)) {
                findings.push({ file: rel, line: idx + 1, kind: "bypass", id: rule.id, what: rule.what });
                break;
            }
        }
    });
    return findings;
}
const locate = (f) => `${f.file}:${f.line} — ${f.what}`;
export function runAgentAutonomyChecks(root) {
    const files = findAgentFiles(root);
    if (files.length === 0) {
        return [
            {
                id: "agent_security.autonomy",
                title: "Agent autonomy and human oversight",
                status: "skip",
                detail: "No agent configuration found — no granted capabilities to assess",
                evidence: { scanned: 0, frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    const findings = [];
    for (const rel of files) {
        const abs = path.join(root, rel);
        try {
            if (fs.statSync(abs).size > MAX_BYTES)
                continue;
            findings.push(...scanForAutonomyRisks(rel, fs.readFileSync(abs, "utf8")));
        }
        catch {
            // Unreadable file is not evidence of a problem.
        }
    }
    const capabilities = findings.filter((f) => f.kind === "capability");
    const bypasses = findings.filter((f) => f.kind === "bypass");
    // The dangerous combination, and the only one worth failing a build over: the
    // agent can do something irreversible AND nobody is being asked first.
    if (capabilities.length > 0 && bypasses.length > 0) {
        const kinds = [...new Set(capabilities.map((c) => c.consequence))].join(", ");
        return [
            {
                id: "agent_security.autonomy",
                title: "Agent autonomy and human oversight",
                status: "fail",
                detail: `Agent can act irreversibly with no human in the loop — ${kinds} capability granted ` +
                    `while approval is bypassed. Capability: ${capabilities.slice(0, 2).map(locate).join("; ")}. ` +
                    `Bypass: ${bypasses.slice(0, 2).map(locate).join("; ")}. ` +
                    `Re-enable confirmation for these tools, or remove the capability.`,
                evidence: {
                    capabilities: capabilities.slice(0, 20),
                    bypasses: bypasses.slice(0, 20),
                    scanned: files.length,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    // Approval switched off, nothing consequential attached yet. Not a failure —
    // but it is the half of the problem that gets forgotten before the other half
    // arrives, so say so now rather than after a payment tool is added.
    if (bypasses.length > 0) {
        return [
            {
                id: "agent_security.autonomy",
                title: "Agent autonomy and human oversight",
                status: "warn",
                detail: `Approval prompts are bypassed (${bypasses.slice(0, 2).map(locate).join("; ")}). ` +
                    `No irreversible capability is attached today — this becomes a blocker the moment one is.`,
                evidence: { bypasses: bypasses.slice(0, 20), scanned: files.length, frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    if (capabilities.length > 0) {
        return [
            {
                id: "agent_security.autonomy",
                title: "Agent autonomy and human oversight",
                status: "pass",
                detail: `${capabilities.length} consequential capability(ies) granted, human approval left intact ` +
                    `(${[...new Set(capabilities.map((c) => c.consequence))].join(", ")})`,
                evidence: { capabilities: capabilities.slice(0, 20), scanned: files.length, frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    return [
        {
            id: "agent_security.autonomy",
            title: "Agent autonomy and human oversight",
            status: "pass",
            detail: `Scanned ${files.length} agent config file(s) — no money-moving, destructive, or impersonating capability granted`,
            evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
        },
    ];
}
