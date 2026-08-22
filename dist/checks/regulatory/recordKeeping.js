import { blankDefinitions, existsInTree, findLine, keyValue, matchesInCode, renderFinding, scanTree, } from "./shared.js";
/**
 * Record-keeping — can anyone reconstruct what the agent did?
 *
 * ## The obligation
 *
 * EU AI Act Article 12 will require high-risk systems to technically allow the
 * automatic recording of events over their lifetime. That duty is **not generally
 * in force until 2 December 2027** (Digital Omnibus). This check still runs: it
 * records whether a durable sink exists in the tree, labelled as evidence for a
 * delayed duty — never as "live now."
 *
 * ISO/IEC 42001 A.6.2.8 and NIST AI RMF MEASURE 2.8 ask for the same artefact
 * from different directions, and every enterprise security questionnaire asks for
 * it in plainer words: *show me what your AI did last Tuesday.*
 *
 * ## Why an autonomous agent makes this urgent rather than routine
 *
 * A tool that only acts when a human clicks has a natural record — the human
 * remembers, and the click is in an access log. An agent that runs unattended
 * overnight has no such fallback. If it did not write down what it did, then
 * nobody knows what it did, and no subsequent investigation can establish it.
 *
 * That is also why the interesting failure is not "no logging library". It is
 * **logging that does not survive**: `console.log` in a container that is
 * discarded on redeploy is not a record. It satisfies every code review and
 * answers no question asked six weeks later.
 *
 * ## What is actually checked
 *
 *   1. Does the agent take consequential actions — spend, delete, send, decide?
 *   2. Is there durable recording anywhere — a log sink, an audit table, an
 *      append-only file, a structured event stream?
 *   3. Is recording *only* ephemeral, i.e. console output and nothing else?
 *   4. Is a retention period configured below the six-month floor?
 *   5. Does anything actively disable or delete the audit trail?
 *
 * Point 5 is the serious one, and it is the only one in this module treated the
 * way deception is treated elsewhere: an agent that erases its own trail has done
 * something categorically different from an agent that forgot to keep one.
 *
 * ## What is deliberately not claimed
 *
 * Whether a given system is "high-risk" under Annex III is a legal
 * classification, not a property of a repository, and this check does not attempt
 * it. Findings are worded as observations about recording practice with an
 * article reference attached.
 */
const FRAMEWORK_REFS = {
    eu: [
        "Art. 12 Record-keeping (high-risk Annex III — delayed until 2027-12-02)",
        "Art. 19 Automatically generated logs (same clock)",
        "Art. 26(6) Deployer log retention (same clock)",
    ],
    iso42001: ["A.6.2.8 AI System Recording of Event Logs", "A.6.2.6 AI System Operation and Monitoring"],
    nist: ["MEASURE 2.8", "MANAGE 4.1"],
};
/* ═══════════════════════════ 1 — actions worth recording ═══ */
/**
 * Actions whose absence from a log would matter to an investigator.
 *
 * Reads are excluded. A record of every query would drown the record of the one
 * transfer, and a log nobody can search is not meaningfully a log.
 */
const CONSEQUENTIAL_ACTION = [
    // `\w*` tail: the actual call is `stripe.charges.create`, and `\bcharge\b`
    // never matches `charges`. A plural silently disabled the money-movement rule.
    { re: /\b(?:charge|paymentIntent|payment_intent|transfer|payout|refund)\w*|\binvoice\.(?:create|pay)|\bsubscription\.(?:create|cancel)/i, what: "money movement" },
    { re: /\b(?:delete|destroy|drop|truncate|purge|remove)(?:Many|Table|Database|Bucket|Object)?\s*\(/i, what: "destructive data operation" },
    { re: /\b(?:sendgrid|mailgun|postmark|nodemailer|twilio|chat\.postMessage)\b/i, what: "outbound message sent on someone's behalf" },
    { re: /\b(?:deploy|release|rollout|scale|terminate[_.]?instance)\s*\(/i, what: "infrastructure change" },
    { re: /\b(?:approve|reject|deny|suspend|ban|revoke)[_.]?(?:user|account|application|claim|request)\b/i, what: "decision applied to an account" },
];
/* ═════════════════════════════════ 2 — durable recording ═══ */
/**
 * Recording that survives the process.
 *
 * The distinction being drawn is durability, not sophistication. A line appended
 * to a file on a mounted volume is a record. A structured log shipped to a sink
 * is a record. A string printed to stdout in an ephemeral container is not, and
 * the difference only becomes visible at the moment somebody needs it.
 */
/**
 * Evidence of durable recording — and it must be evidence of a *call*, not of a
 * vocabulary.
 *
 * The original patterns matched bare words: `audit_log`, `ledger`, `event_log`
 * anywhere in a file. A red-team agent defeated the whole check by naming things
 * suggestively — a constant called `AUDIT_LOG_ENABLED`, a comment mentioning the
 * audit trail, an interface named `LedgerEntry` — while writing nothing anywhere.
 * The check was reading intent off identifiers, which is exactly the mistake the
 * assertion detector in `workmanship` had to be corrected for.
 *
 * Every pattern now requires a call or a write. A name proves someone thought
 * about recording; only an invocation proves anything was recorded.
 */
const DURABLE_RECORDING = [
    // A logging library, imported or constructed — not merely named in prose.
    { re: /\b(?:from|require)\s*\(?\s*['"](?:winston|pino|bunyan|log4js|serilog|structlog|zerolog)['"]|\b(?:winston|pino|bunyan)\s*\(/i, what: "structured logging library" },
    // A logger being called: `logger.info(...)`, `log.warn(...)`.
    { re: /\b(?:logger|log)\s*\.\s*(?:info|warn|error|debug|trace|event|audit)\s*\(/i, what: "logger invocation" },
    // An audit helper being *called*, not declared as a constant.
    //
    // Three shapes, because real code writes it three ways and an earlier version
    // of this rule accepted only the first two. `recordAction('settle', id, out)`
    // — a perfectly ordinary audit helper — was flagged as *missing* logging,
    // because the rule looked for the keyword inside the argument list and this
    // one carries it in the function name. Requiring a call is right; requiring the
    // evidence to appear in one particular position was not.
    {
        re: /\b\w*(?:audit|activity|event)\w*(?:Log|Trail|Record|Event)?\s*\.\s*\w+\s*\(/i,
        what: "audit record written",
    },
    {
        re: /\b(?:record|write|append|emit|persist|track)(?:Action|Event|Audit|Entry|Log|Activity)\w*\s*\(/i,
        what: "audit helper invoked",
    },
    {
        re: /\b(?:record|write|append|emit|persist)\w*\s*\(\s*[^)]*\b(?:audit|event|action)/i,
        what: "audit record written",
    },
    { re: /\b(?:appendFileSync|appendFile|createWriteStream|WriteStream)\s*\(/i, what: "append-only file write" },
    // A telemetry sink being configured or called.
    { re: /\b(?:cloudwatch|datadog|splunk|elastic(?:search)?|loki|opentelemetry|otel|sentry)\s*[.(]|from\s*['"]@?(?:datadog|sentry|opentelemetry)/i, what: "log or telemetry sink" },
    { re: /\bINSERT\s+INTO\s+\w*(?:audit|log|event)\w*|\.(?:insert|create)\s*\(\s*\{[^}]*\b(?:audit|event|action)\b/i, what: "audit record written to a datastore" },
    { re: /\b(?:kafka|kinesis|pubsub|eventbridge|rabbitmq)\s*[.(]|\bproducer\s*\.\s*send\s*\(/i, what: "event stream" },
    { re: /\bledger\s*\.\s*\w+\s*\(|\bappendToLedger\s*\(/i, what: "ledger write" },
];
/** Output that does not survive a redeploy. */
const EPHEMERAL_ONLY = /\bconsole\.(?:log|info|debug|warn|error)\s*\(|\bprint\s*\(/;
/* ═══════════════════════════ 3 — retention and erasure ═══ */
/** A configured retention period, captured so the number can be compared. */
// The unit group is captured before the closing quote is consumed, so both
// `log_retention_days: 7` and `"retention": "7d"` parse.
const RETENTION_CONFIG = /["']?(?:log[_.]?)?retention(?:[_.]?(?:days|period|hours|in[_.]?days))?["']?\s*[:=]\s*["']?(\d+)\s*(d|day|days|h|hour|hours|mo|month|months)?\b/i;
/** Actions that remove the trail rather than keep it. */
const TRAIL_DESTRUCTION = [
    // `\w*` tail: the call is `deleteAuditLogs`, where `s?\b` stops at `Logs`.
    { re: /(?:delete|drop|truncate|purge|clear|wipe)[_.]?(?:audit|log|event|trail|history)\w*/i, what: "code deletes the audit trail" },
    { re: keyValue("audit[_.]?(?:enabled|on)|logging[_.]?(?:enabled|on)|log[_.]?(?:enabled|on)", "false|0|off|no"), what: "logging switched off in configuration" },
    { re: /disable[_.]?(?:audit|logging|log)\w*/i, what: "logging explicitly disabled" },
    { re: keyValue("history|log[_.]?history", "false|0|none"), what: "history retention switched off" },
];
/** Six months, expressed in days — the Art. 19 floor. */
const RETENTION_FLOOR_DAYS = 180;
/** Normalise a retention value to days so numbers with different units compare. */
export function retentionToDays(value, unit) {
    const u = (unit ?? "d").toLowerCase();
    if (u.startsWith("h"))
        return value / 24;
    if (u.startsWith("mo") || u === "m")
        return value * 30;
    return value;
}
/* ═══════════════════════════════════════════════════ entry ═══ */
export function scanRecordKeeping(files) {
    const findings = [];
    const live = files.filter((f) => !f.isTestOrFixture);
    // Destroying or disabling the trail — always reported, wherever it appears.
    for (const f of live) {
        for (const rule of TRAIL_DESTRUCTION) {
            const line = findLine(f.text, rule.re);
            if (line) {
                findings.push({
                    file: f.rel,
                    line,
                    article: "Art. 12",
                    detail: `${rule.what} — an agent that does not keep its trail cannot be investigated afterwards`,
                    severity: "hard",
                });
                break;
            }
        }
    }
    // Retention below the six-month floor.
    //
    // Scoped to configuration files. A retention period is declared in JSON, YAML,
    // or an env file — never in the middle of application logic — so scanning code
    // for it finds only strings that happen to look like config. This project's own
    // demo script was reported for a value inside a fixture it prints.
    for (const f of live.filter((x) => x.isConfig)) {
        const lines = f.text.split(/\r?\n/);
        for (let i = 0; i < lines.length; i += 1) {
            const m = RETENTION_CONFIG.exec(blankDefinitions(lines[i]));
            if (!m)
                continue;
            const days = retentionToDays(Number(m[1]), m[2]);
            if (days > 0 && days < RETENTION_FLOOR_DAYS) {
                findings.push({
                    file: f.rel,
                    line: i + 1,
                    article: "Art. 19",
                    detail: `log retention configured at approximately ${Math.round(days)} day(s) — Art. 19 treats ` +
                        `six months as the floor for automatically generated logs`,
                    severity: "soft",
                });
            }
            break;
        }
    }
    // Durability is a property of the repository, not of one file: a logger
    // configured centrally serves every call site. Asking per-file would fail the
    // codebases that factored logging out properly.
    const durable = DURABLE_RECORDING.map((r) => existsInTree(files, r.re)).find((r) => r.found);
    if (!durable) {
        for (const f of live.filter((x) => x.isCode)) {
            for (const rule of CONSEQUENTIAL_ACTION) {
                const line = findLine(f.text, rule.re);
                if (!line)
                    continue;
                const ephemeralOnly = matchesInCode(f.text, EPHEMERAL_ONLY);
                findings.push({
                    file: f.rel,
                    line,
                    article: "Art. 12",
                    detail: ephemeralOnly
                        ? `${rule.what} recorded only with console output — process logs do not survive a redeploy, ` +
                            `so this is not a record anyone can consult later`
                        : `${rule.what} with no durable recording found anywhere in this repository — ` +
                            `nobody can reconstruct what this agent did`,
                    severity: "hard",
                });
                break;
            }
        }
    }
    return findings;
}
export function runRecordKeepingChecks(root) {
    const files = scanTree(root);
    if (files.length === 0) {
        return [{
                id: "regulatory.record_keeping",
                title: "Record-keeping (EU AI Act Art. 12)",
                status: "skip",
                detail: "No readable source files — nothing to assess",
                evidence: { scanned: 0, frameworks: FRAMEWORK_REFS },
            }];
    }
    const findings = scanRecordKeeping(files);
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    const hasAction = files.some((f) => !f.isTestOrFixture && f.isCode && CONSEQUENTIAL_ACTION.some((r) => matchesInCode(f.text, r.re)));
    if (!hasAction && findings.length === 0) {
        return [{
                id: "regulatory.record_keeping",
                title: "Record-keeping (EU AI Act Art. 12)",
                status: "skip",
                detail: `Scanned ${files.length} file(s) — this system takes no consequential action, so there is ` +
                    `nothing whose absence from a log would matter`,
                evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    if (hard.length > 0) {
        return [{
                id: "regulatory.record_keeping",
                title: "Record-keeping (EU AI Act Art. 12)",
                status: "fail",
                detail: `${hard.length} record-keeping finding(s) — what this agent did cannot be reconstructed. ` +
                    hard.slice(0, 3).map(renderFinding).join("; ") +
                    (hard.length > 3 ? ` (+${hard.length - 3} more)` : ""),
                evidence: {
                    hard: hard.slice(0, 20),
                    soft: soft.slice(0, 10),
                    scanned: files.length,
                    retention_floor_days: RETENTION_FLOOR_DAYS,
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    if (soft.length > 0) {
        return [{
                id: "regulatory.record_keeping",
                title: "Record-keeping (EU AI Act Art. 12)",
                status: "warn",
                detail: `${soft.length} retention finding(s). ` + soft.slice(0, 2).map(renderFinding).join("; "),
                evidence: { soft: soft.slice(0, 20), scanned: files.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    return [{
            id: "regulatory.record_keeping",
            title: "Record-keeping (EU AI Act Art. 12)",
            status: "pass",
            detail: `Scanned ${files.length} file(s) — consequential actions are recorded durably, retention is not ` +
                `configured below the six-month floor, and nothing deletes the trail`,
            evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
        }];
}
