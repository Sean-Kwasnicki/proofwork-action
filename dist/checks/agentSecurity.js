import fs from "node:fs";
import path from "node:path";
/**
 * Agent security — can this agent be turned against its owner?
 *
 * Proofwork's other checks ask whether the agent did real work. This one asks a
 * different question: if an attacker gets text in front of this agent, what can
 * they take? Prompt injection is not exotic — any agent that reads a web page, an
 * issue comment, or a user-supplied document is processing attacker-controlled
 * input, and anything reachable from the agent's context is reachable by that input.
 *
 * The highest-value thing reachable from context is a credential. A key sitting in
 * a prompt file or an MCP config is not "config" — it is one successful injection
 * away from being exfiltrated, and unlike a leaked key in source it is *deliberately*
 * placed where the model can read it.
 *
 * Scope is deliberately narrow and static: it reads files the agent is configured
 * from. It does not probe a running agent — that requires the target owner's written
 * authorization and belongs in an engagement, not a build gate.
 *
 * Evidences EU AI Act Art. 15 (accuracy, robustness and cybersecurity) and
 * NIST AI RMF MEASURE 2.7 (security and resilience evaluated and documented).
 */
const FRAMEWORK_REFS = {
    iso42001: ["A.6.2.4 AI-System Verification and Validation"],
    nist: ["MEASURE 2.7", "MANAGE 2.3"],
    eu: ["Art. 15 Accuracy, Robustness and Cybersecurity"],
};
/** Files an agent is configured or prompted from — attacker-reachable context. */
const AGENT_FILE_PATTERNS = [
    /(^|\/)\.mcp\.json$/i,
    /(^|\/)mcp\.json$/i,
    /(^|\/)\.cursor\/mcp\.json$/i,
    /(^|\/)claude_desktop_config\.json$/i,
    /(^|\/)AGENTS?\.md$/i,
    /(^|\/)CLAUDE\.md$/i,
    /(^|\/)\.cursor\/rules\/.*\.mdc$/i,
    /(^|\/)prompts?\//i,
    /(^|\/)system[-_]?prompt[^/]*$/i,
    /\.prompt(\.[a-z]+)?$/i,
];
/** Directories never worth walking. */
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork",
]);
const MAX_FILES = 400;
const MAX_BYTES = 512 * 1024;
/**
 * Patterns anchored on issuer-specific prefixes rather than generic entropy.
 * Entropy heuristics produce false positives on hashes and base64 assets, and a
 * security check that cries wolf gets switched off — which is strictly worse than
 * not having it.
 */
const SECRET_RULES = [
    { id: "anthropic_key", re: /\bsk-ant-[a-z0-9-]{8,}/i, what: "Anthropic API key" },
    { id: "openai_key", re: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}/, what: "OpenAI API key" },
    { id: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, what: "AWS access key id" },
    { id: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{16,}/, what: "GitHub token" },
    { id: "google_key", re: /\bAIza[0-9A-Za-z_-]{20,}/, what: "Google API key" },
    { id: "slack_token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, what: "Slack token" },
    { id: "stripe_key", re: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}/, what: "Stripe key" },
    { id: "private_key_block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, what: "private key block" },
    { id: "bearer_literal", re: /\bAuthorization\s*:\s*["']?Bearer\s+[A-Za-z0-9._-]{20,}/i, what: "hardcoded bearer token" },
];
/**
 * Placeholder detection, scoped to the matched credential rather than the line.
 *
 * This previously tested the whole line, which meant appending a harmless comment
 * — `sk-ant-<real key>  # example config` — suppressed detection of a genuine
 * secret. One word defeated the entire check. Matching against the captured
 * credential closes that: a placeholder is a property of the value, not of any
 * text that happens to share the line with it.
 */
const PLACEHOLDER_VALUE = /(YOUR[_-]?|EXAMPLE|PLACEHOLDER|REPLACE[_-]?ME|DUMMY|SAMPLE|TEST[_-]?KEY|xxxx+|\.\.\.|<|>|\$\{)/i;
/** A credential referenced indirectly is not a credential sitting in context. */
const INDIRECTION = /(process\.env|os\.environ|System\.getenv|\$\{[A-Z_]+\}|ENV\[)/;
/**
 * Base64 wrapping is the cheapest way to hide a key from an issuer pattern, and a
 * key is no less reachable for being encoded — the agent can decode it as easily
 * as we can. Candidates are decoded and re-tested against the same rules.
 */
const BASE64_CANDIDATE = /\b[A-Za-z0-9+/]{24,}={0,2}\b/g;
function isAgentFile(rel) {
    const norm = rel.replace(/\\/g, "/");
    return AGENT_FILE_PATTERNS.some((re) => re.test(norm));
}
function walk(root, dir, out) {
    if (out.length >= MAX_FILES)
        return;
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const entry of entries) {
        if (out.length >= MAX_FILES)
            return;
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".") && entry.name !== ".cursor")
                continue;
            walk(root, abs, out);
        }
        else if (entry.isFile()) {
            const rel = path.relative(root, abs).replace(/\\/g, "/");
            if (isAgentFile(rel))
                out.push(rel);
        }
    }
}
/** Collect the agent-reachable configuration and prompt files under `root`. */
export function findAgentFiles(root) {
    const out = [];
    walk(root, root, out);
    // .cursor is skipped by the dotfile rule above unless explicitly allowed; also
    // check well-known dot-locations directly so a missing walk never hides a file.
    for (const rel of [".mcp.json", ".cursor/mcp.json", "claude_desktop_config.json"]) {
        if (!out.includes(rel) && fs.existsSync(path.join(root, rel)))
            out.push(rel);
    }
    return [...new Set(out)].sort();
}
/** Test one string against every issuer rule, ignoring obvious placeholders. */
function matchSecret(candidate) {
    for (const rule of SECRET_RULES) {
        const found = rule.re.exec(candidate);
        if (!found)
            continue;
        // Judge the captured credential, never the surrounding line.
        if (PLACEHOLDER_VALUE.test(found[0]))
            continue;
        return rule;
    }
    return undefined;
}
/** Decode base64-looking runs and re-test them. Encoding hides nothing from the agent. */
function matchEncodedSecret(line) {
    for (const candidate of line.match(BASE64_CANDIDATE) ?? []) {
        let decoded;
        try {
            decoded = Buffer.from(candidate, "base64").toString("utf8");
        }
        catch {
            continue;
        }
        // Reject binary noise: a decoded credential is printable ASCII.
        if (!/^[\x20-\x7e]{8,}$/.test(decoded))
            continue;
        const rule = matchSecret(decoded);
        if (rule)
            return rule;
    }
    return undefined;
}
/** Scan one file's text for credentials that would be reachable from agent context. */
export function scanForExposedSecrets(rel, text) {
    const findings = [];
    text.split(/\r?\n/).forEach((line, idx) => {
        // A reference through the environment is not a secret in context.
        if (INDIRECTION.test(line))
            return;
        const direct = matchSecret(line);
        if (direct) {
            findings.push({ file: rel, line: idx + 1, rule: direct.id, what: direct.what });
            return; // one finding per line is enough to act on
        }
        const encoded = matchEncodedSecret(line);
        if (encoded) {
            findings.push({
                file: rel,
                line: idx + 1,
                rule: `${encoded.id}_base64`,
                what: `${encoded.what} (base64-encoded)`,
            });
        }
    });
    return findings;
}
export function runAgentSecurityChecks(root) {
    const files = findAgentFiles(root);
    if (files.length === 0) {
        return [
            {
                id: "agent_security.secret_exposure",
                title: "Agent secret exposure",
                status: "skip",
                detail: "No agent configuration or prompt files found — nothing reachable from agent context",
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
            findings.push(...scanForExposedSecrets(rel, fs.readFileSync(abs, "utf8")));
        }
        catch {
            // Unreadable file: not evidence of a problem, and not worth failing over.
        }
    }
    if (findings.length > 0) {
        const located = findings
            .slice(0, 3)
            .map((f) => `${f.file}:${f.line} — ${f.what}`)
            .join("; ");
        const more = findings.length > 3 ? ` (+${findings.length - 3} more)` : "";
        return [
            {
                id: "agent_security.secret_exposure",
                title: "Agent secret exposure",
                status: "fail",
                detail: `${findings.length} credential(s) reachable from agent context → ${located}${more}. ` +
                    `A prompt injection can read anything the agent can read — move these to environment ` +
                    `variables and rotate them.`,
                evidence: {
                    findings: findings.slice(0, 20),
                    scanned: files.length,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    return [
        {
            id: "agent_security.secret_exposure",
            title: "Agent secret exposure",
            status: "pass",
            detail: `Scanned ${files.length} agent config/prompt file(s) — no credentials reachable from agent context`,
            evidence: { scanned: files.length, files: files.slice(0, 20), frameworks: FRAMEWORK_REFS },
        },
    ];
}
