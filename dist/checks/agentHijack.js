import fs from "node:fs";
import path from "node:path";
import { isForeignTree } from "./testPaths.js";
import { findAgentFiles } from "./agentSecurity.js";
import { suppressedWithReason } from "./ignoreDirective.js";
/**
 * Agent-to-agent takeover.
 *
 * Every other layer in this gate asks whether an agent did its own job properly.
 * This one asks a question that only exists because agents now talk to each
 * other: **can this agent be used to take control of a different agent?**
 *
 * The threat is not hypothetical and it is not the same as prompt injection
 * against a human-facing chatbot. In a multi-agent system one agent's output is
 * the next agent's input, so a single hijacked agent inherits the trust
 * relationships of everything downstream of it. The compromise travels inside the
 * agent communication layer, where no network control can see it.
 *
 * ## Mapped to a published taxonomy, not to our own opinion
 *
 * Findings cite the OWASP Top 10 for Agentic Applications (ASI, 2026):
 *
 *   ASI01  Agent Goal Hijack ......... instructions that redirect an agent's objective
 *   ASI03  Agent Identity & Privilege  delegation that widens authority
 *   ASI04  Agentic Supply Chain ...... trusting a tool or schema fetched at runtime
 *   ASI07  Insecure Inter-Agent Comms  unauthenticated instruction channels
 *   ASI10  Rogue Agents .............. objectives set beyond the operator's intent
 *
 * Citing someone else's taxonomy is deliberate. A vendor that invents its own
 * threat categories is grading against a rubric it wrote, and a buyer's security
 * team has no way to check the work. ASI numbers are auditable by someone who has
 * never heard of us.
 *
 * ## The rule this layer enforces
 *
 * An agent may do what its operator authorised. It may not acquire authority it
 * was not given, and it may not hand authority to something else that was not
 * given it either. That is the same rule societies apply to people, and it is the
 * rule that keeps a multi-agent system from becoming a jungle: capability has to
 * be traceable to a human who agreed to it.
 *
 * Every rule below is syntactic and deterministic. No model judges anything.
 */
const FRAMEWORK_REFS = {
    owasp_asi: ["ASI01", "ASI03", "ASI04", "ASI07", "ASI10"],
    iso42001: ["A.6.2.4 AI-System Verification and Validation", "A.9.2 Responsible Use"],
    nist: ["MANAGE 2.3", "MEASURE 2.7"],
    eu: ["Art. 14 Human Oversight", "Art. 15 Accuracy, Robustness and Cybersecurity"],
};
const MAX_BYTES = 512 * 1024;
/* ══════════════════════════════════════════ 1 — instruction override (ASI01) ═══ */
/**
 * Text that exists to redirect another agent's objective.
 *
 * These phrases appear in agent-readable files — AGENTS.md, MCP manifests, rule
 * files, issue templates. A human reading the file sees documentation. The next
 * agent to read it sees an instruction, because to an agent there is no
 * difference; the file *is* the prompt.
 *
 * Matching is anchored on the imperative construction rather than on keywords, so
 * ordinary prose that happens to discuss prompt injection is not itself flagged.
 * Documentation about this attack class is common in exactly the repositories
 * that would install us, and flagging our own customers' security notes would be
 * a fast way to get uninstalled.
 */
const OVERRIDE_PATTERNS = [
    {
        re: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|earlier|above|system|initial)\s+(?:instruction|prompt|rule|direction|message)/i,
        what: "instructs a reader to discard its prior instructions",
    },
    {
        re: /\byou\s+are\s+now\s+(?:a|an|the)\b(?!.*\bexample\b)/i,
        what: "reassigns the reading agent's role",
    },
    {
        re: /\b(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|prompt|directive)s?\s*:/i,
        what: "presents itself as a replacement system prompt",
    },
    {
        re: /\bdo\s+not\s+(?:tell|inform|mention|report|reveal)\s+(?:the\s+)?(?:user|operator|human|owner)\b/i,
        what: "instructs the reader to conceal its actions from its operator",
    },
    {
        re: /\b(?:without|skip|bypass|no need for)\s+(?:asking|confirmation|approval|permission)\b/i,
        what: "instructs the reader to act without the approval step",
    },
];
/* ═══════════════════════════════════════════════ 2 — tool poisoning (ASI04) ═══ */
/**
 * A tool *description* that contains instructions.
 *
 * An MCP tool description is documentation from the human's point of view and
 * context from the agent's. An attacker who controls a tool's metadata can put
 * an instruction there, and it lands in the agent's context every time the tool
 * list is enumerated — before the tool is ever called.
 *
 * A description says what a tool does. Anything addressed to the reader in the
 * second person, or telling it what to do first, is not a description.
 */
const POISON_PATTERNS = [
    {
        re: /\b(?:before|prior to)\s+(?:using|calling|invoking)\s+this\s+tool[,\s]+(?:you\s+must|always|first)\b/i,
        what: "tool description issues a precondition instruction to the agent",
    },
    {
        re: /\balways\s+(?:call|invoke|use)\s+(?:this|the)\s+\w+\s+(?:tool\s+)?(?:first|before)\b/i,
        what: "tool description asserts call-ordering priority over the agent's plan",
    },
    {
        re: /<\s*(?:system|important|instruction)s?\s*>/i,
        what: "tool metadata contains pseudo-system markup",
    },
];
/* ════════════════════════════════════ 3 — unauthenticated channel (ASI07/03) ═══ */
/**
 * Code that sends instructions to another agent with nothing establishing who
 * is asking.
 *
 * If agent A can post a task to agent B's endpoint without proving identity, then
 * anything that can reach that endpoint can drive agent B — and in a multi-agent
 * deployment, "anything that can reach it" includes every agent already inside
 * the perimeter. Message spoofing between agents is ASI07's named example.
 */
const AGENT_ENDPOINT = /\b(?:fetch|axios|request|post|send|invoke|dispatch)\s*(?:\.\w+\s*)?\(\s*[`'"][^`'"]*\/(?:agent|a2a|task|delegate|handoff|subagent|worker)s?\b/i;
/** Signals that an outbound agent call carries proof of who is calling. */
const AUTH_SIGNAL = /\b(?:Authorization|authorization|api[_-]?key|apiKey|bearer|signature|signed|hmac|token|credential|mTLS|clientCert)\b/;
/* ══════════════════════════════════════════ 4 — privilege delegation (ASI03) ═══ */
/**
 * A sub-agent created with authority the parent did not have to be granted.
 *
 * This is the agentic form of privilege escalation and it is easy to write by
 * accident: spawning a worker with `approval: never` or `permissions: "*"` while
 * the parent runs under a human-approval policy. The child then does what the
 * parent was forbidden to, and the audit trail records the child as the actor.
 */
/**
 * Call sites that create another agent.
 *
 * `\w*` between the verb and the paren is load-bearing: the common spelling is
 * `spawnAgent({...})`, where the verb is followed by more identifier rather than
 * by the bracket. Anchoring on the verb alone matched nothing real.
 */
const DELEGATION_CONTEXT = /\b(?:spawn|create|launch|start|fork|delegate|register|add)\w*\s*[({]|\b\w*(?:agent|worker|subagent|sub_agent)\w*\s*[({]/i;
const WIDE_AUTHORITY = [
    { re: /\b(?:approval|confirm(?:ation)?|require_approval|humanInTheLoop)\s*[:=]\s*(?:['"]?never['"]?|false|0)\b/i, what: "approval disabled for the delegated agent" },
    { re: /\b(?:permissions?|scopes?|allowedTools?|capabilities)\s*[:=]\s*\[?\s*['"]\*['"]/i, what: "delegated agent granted every capability" },
    { re: /\b(?:bypassPermissions|dangerouslySkipPermissions|skipPermissions|yolo)\s*[:=]\s*true\b/i, what: "permission enforcement disabled for the delegated agent" },
    { re: /\bsandbox\s*[:=]\s*(?:false|['"]none['"])/i, what: "delegated agent runs without a sandbox" },
];
/* ═════════════════════════════════ 5 — remote instruction source (ASI04/01) ═══ */
/**
 * Instructions fetched at runtime from somewhere mutable.
 *
 * A system prompt loaded from a URL means whoever controls that URL controls the
 * agent, permanently and without touching this repository. It is the agentic
 * supply chain in its most direct form: the code passes review once and the
 * behaviour is editable forever.
 */
const REMOTE_INSTRUCTION = /\b(?:systemPrompt|system_prompt|instructions?|persona|rules)\s*[:=]\s*(?:await\s+)?(?:fetch|axios|got|request|http\.get|urlopen|requests\.get)\s*\(/i;
/* ════════════════════════════════════════════════════════════════ scanning ═══ */
const isCodeFile = (p) => /\.[cm]?[jt]sx?$|\.py$|\.rb$|\.go$/i.test(p);
const isConfigFile = (p) => /\.(json|ya?ml|toml)$/i.test(p);
/**
 * Lines that are demonstrating the attack rather than committing it.
 *
 * Security repositories, our own included, contain these strings on purpose. A
 * check that cannot tell a test fixture from a live payload will flag every
 * security team that installs it, and they are the buyers most likely to
 * evaluate us seriously.
 */
const LOOKS_LIKE_A_FIXTURE = /\b(?:test|spec|fixture|example|sample|demo|mock|docs?)\b/i;
const isFixturePath = (p) => LOOKS_LIKE_A_FIXTURE.test(p) || /(^|\/)(?:__tests__|testdata)\//i.test(p);
export function scanForHijack(rel, text) {
    const findings = [];
    const lines = text.split(/\r?\n/);
    const agentReadable = isAgentReadable(rel);
    lines.forEach((line, i) => {
        const at = i + 1;
        /**
         * A recorded review closes the finding this check asks for.
         *
         * The soft finding's own text is "review that these are fixtures" — and until
         * now there was no way to say that you had. A repository that legitimately
         * ships attack fixtures, which is every security tool and this one, could
         * never reach zero warnings, so `failOnWarn` made it permanently unmergeable
         * for the buyers most likely to evaluate us seriously.
         *
         * A **reason is required** here, with no bare-directive budget, unlike
         * `workmanship`. Silencing a takeover pattern is a security decision, and the
         * whole value of the suppression is the sentence explaining why the line is a
         * demonstration rather than a capability. A bare `proofwork-ignore` would
         * record that someone wanted the warning gone, which is not the same thing.
         */
        if (suppressedWithReason(line, i > 0 ? lines[i - 1] ?? "" : ""))
            return;
        // ASI01 — instruction override, only meaningful in files an agent reads.
        if (agentReadable) {
            for (const p of OVERRIDE_PATTERNS) {
                if (p.re.test(line)) {
                    findings.push({
                        file: rel, line: at, kind: "instruction_override", asi: "ASI01",
                        detail: `${p.what} — this file is read into an agent's context`,
                        severity: "hard",
                    });
                    break;
                }
            }
        }
        // ASI04 — tool poisoning in agent manifests.
        if (isConfigFile(rel) && agentReadable) {
            for (const p of POISON_PATTERNS) {
                if (p.re.test(line)) {
                    findings.push({
                        file: rel, line: at, kind: "tool_poisoning", asi: "ASI04",
                        detail: p.what,
                        severity: "hard",
                    });
                    break;
                }
            }
        }
        if (!isCodeFile(rel))
            return;
        // ASI07 — instruction channel with no caller identity. Auth may sit on a
        // nearby line (headers object, interceptor), so look at a small window
        // rather than the single line, or every well-built client trips this.
        if (AGENT_ENDPOINT.test(line)) {
            const window = lines.slice(Math.max(0, i - 6), i + 12).join("\n");
            if (!AUTH_SIGNAL.test(window)) {
                findings.push({
                    file: rel, line: at, kind: "unauthenticated_agent_channel", asi: "ASI07",
                    detail: "instructions are sent to another agent with nothing establishing the caller's identity — " +
                        "any party that can reach this endpoint can drive that agent",
                    severity: "hard",
                });
            }
        }
        // ASI03 — delegation that widens authority.
        if (DELEGATION_CONTEXT.test(line)) {
            const window = lines.slice(i, i + 14).join("\n");
            for (const w of WIDE_AUTHORITY) {
                if (w.re.test(window)) {
                    findings.push({
                        file: rel, line: at, kind: "privilege_delegation", asi: "ASI03",
                        detail: `${w.what} — a delegated agent must not exceed the authority of the agent that created it`,
                        severity: "hard",
                    });
                    break;
                }
            }
        }
        // ASI04/ASI01 — instructions loaded from somewhere mutable.
        if (REMOTE_INSTRUCTION.test(line)) {
            findings.push({
                file: rel, line: at, kind: "remote_instruction_source", asi: "ASI04",
                detail: "the agent's instructions are fetched at runtime — whoever controls that source controls this agent, " +
                    "without ever touching this repository",
                severity: "hard",
            });
        }
    });
    return findings;
}
const AGENT_READABLE_EXTRA = [
    /(^|\/)\.github\/ISSUE_TEMPLATE\//i,
    /(^|\/)\.github\/PULL_REQUEST_TEMPLATE/i,
    /(^|\/)README\.md$/i,
    /(^|\/)CONTRIBUTING\.md$/i,
    /(^|\/)\.claude\//i,
    /(^|\/)\.agent[s]?\//i,
    /(^|\/)skills?\//i,
];
/** Files whose contents land in some agent's context window. */
export function isAgentReadable(rel) {
    const p = rel.replace(/\\/g, "/");
    if (AGENT_READABLE_EXTRA.some((re) => re.test(p)))
        return true;
    return [
        /(^|\/)\.mcp\.json$/i, /(^|\/)mcp\.json$/i, /(^|\/)\.cursor\//i,
        /(^|\/)claude_desktop_config\.json$/i, /(^|\/)AGENTS?\.md$/i,
        /(^|\/)CLAUDE\.md$/i, /(^|\/)prompts?\//i,
        /(^|\/)system[-_]?prompt[^/]*$/i, /\.prompt(\.[a-z]+)?$/i,
    ].some((re) => re.test(p));
}
/* ═══════════════════════════════════════════════════════════════════ entry ═══ */
const label = (f) => `${f.file}:${f.line} [${f.asi}] ${f.detail}`;
export function runAgentHijackChecks(root) {
    const candidates = new Set(findAgentFiles(root));
    // Code files can open an instruction channel or delegate authority even when
    // they are not themselves agent-readable, so they are scanned too.
    for (const rel of walkCode(root))
        candidates.add(rel);
    const findings = [];
    let scanned = 0;
    for (const rel of candidates) {
        const abs = path.join(root, rel);
        try {
            if (!fs.existsSync(abs) || fs.statSync(abs).size > MAX_BYTES)
                continue;
            const text = fs.readFileSync(abs, "utf8");
            scanned += 1;
            const found = scanForHijack(rel, text);
            // A fixture demonstrating an attack is evidence of a security team, not of
            // a compromise. Recorded as soft so it appears without blocking a merge.
            findings.push(...(isFixturePath(rel) ? found.map((f) => ({ ...f, severity: "soft" })) : found));
        }
        catch {
            continue;
        }
    }
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    if (hard.length > 0) {
        return [{
                id: "agent_security.hijack",
                title: "Agent-to-agent takeover",
                status: "fail",
                detail: `${hard.length} takeover finding(s) — this agent could be used to control another. ` +
                    hard.slice(0, 3).map(label).join("; ") +
                    (hard.length > 3 ? ` (+${hard.length - 3} more)` : ""),
                evidence: { hard: hard.slice(0, 20), soft: soft.slice(0, 10), scanned, frameworks: FRAMEWORK_REFS },
            }];
    }
    if (soft.length > 0) {
        return [{
                id: "agent_security.hijack",
                title: "Agent-to-agent takeover",
                status: "warn",
                detail: `${soft.length} takeover pattern(s) in test or example files — review that these are fixtures. ` +
                    soft.slice(0, 2).map(label).join("; "),
                evidence: { soft: soft.slice(0, 20), scanned, frameworks: FRAMEWORK_REFS },
            }];
    }
    return [{
            id: "agent_security.hijack",
            title: "Agent-to-agent takeover",
            status: "pass",
            detail: `Scanned ${scanned} agent-reachable file(s) — no instruction override, tool poisoning, ` +
                `unauthenticated agent channel, or authority-widening delegation found`,
            evidence: { scanned, frameworks: FRAMEWORK_REFS },
        }];
}
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
function walkCode(root, max = 500) {
    const out = [];
    const stack = [root];
    while (stack.length && out.length < max) {
        const dir = stack.pop();
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            if (out.length >= max)
                break;
            const abs = path.join(dir, e.name);
            if (e.isDirectory()) {
                // A nested repository belongs to another project; its code is not ours.
                if (!SKIP_DIRS.has(e.name) && !isForeignTree(abs))
                    stack.push(abs);
            }
            else if (isCodeFile(e.name)) {
                out.push(path.relative(root, abs).replace(/\\/g, "/"));
            }
        }
    }
    return out;
}
