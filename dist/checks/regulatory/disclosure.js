import { existsInTree, findLine, keyValue, matchesInCode, renderFinding, scanTree, } from "./shared.js";
/**
 * Transparency — does the agent tell people it is an agent?
 *
 * ## Why this check exists, and why now
 *
 * EU AI Act Article 50 became applicable on **2 August 2026**. Its first
 * paragraph is the one that bites autonomous agents hardest, and it is short:
 * a system that interacts directly with natural persons must be designed so
 * those persons are informed they are dealing with an AI, unless that is obvious
 * to a reasonably well-informed observer.
 *
 * The second paragraph covers generated content. Synthetic audio, image, video,
 * and text must be marked in a machine-readable format and detectable as
 * artificially generated. Systems already on the market before 2 August 2026 have
 * until 2 December 2026 for the machine-readable marking specifically.
 *
 * This is the obligation an autonomous agent is *most* likely to breach and
 * *least* likely to notice, because the breach happens at the moment the agent
 * does its job well. An agent that drafts a warm, fluent reply and sends it under
 * a human-sounding name has done exactly what it was built to do, and has also
 * put its operator on the wrong side of a live regulation.
 *
 * ## What is actually checked
 *
 * Three mechanically decidable questions:
 *
 *   1. Does the code open a channel to a natural person — email, SMS, chat,
 *      voice, a support reply?
 *   2. Is there any AI identification anywhere near that channel?
 *   3. Does anything *actively suppress* identification — a flag that strips a
 *      disclaimer, a config that hides the bot label?
 *
 * The third is the serious one. Absent disclosure is usually an oversight;
 * removed disclosure is a decision, and it is reported as a distinct and heavier
 * finding for that reason.
 *
 * ## What is deliberately not claimed
 *
 * This check cannot determine compliance. Disclosure may legitimately live in a
 * UI layer in another repository, an exemption may apply, or the counterparty may
 * not be a natural person at all. Every message below is an observation about
 * code with an article reference attached — never a verdict about a company.
 */
const FRAMEWORK_REFS = {
    eu: [
        "Art. 50(1) Disclosure of AI interaction",
        "Art. 50(2) Machine-readable marking of synthetic content",
        "Art. 50(5) Information provided at first interaction",
    ],
    iso42001: ["A.8.2 Information for Interested Parties", "A.9.2 Responsible Use"],
    nist: ["GOVERN 4.2", "MAP 3.4"],
    owasp_asi: ["ASI09 Human-Agent Trust Exploitation"],
};
/* ════════════════════════════ 1 — channels that reach a person ═══ */
/**
 * Outbound channels that terminate at a human being.
 *
 * Machine-to-machine calls are excluded on purpose: Article 50(1) is about
 * natural persons, and flagging a webhook to an internal service would be noise
 * that trains people to switch the check off.
 */
const HUMAN_CHANNELS = [
    { re: /\b(?:sendgrid|mailgun|postmark|nodemailer|ses\.sendEmail|smtp)\b/i, what: "outbound email to a person" },
    { re: /\b(?:twilio|vonage|messagebird)\b|\bsend[_.]?sms\b/i, what: "outbound SMS to a person" },
    { re: /\bchat\.postMessage\b|\b(?:slack|discord|teams)[_.]?(?:webhook|send|post)\b/i, what: "message posted to a person in chat" },
    { re: /\b(?:intercom|zendesk|freshdesk|helpscout|front)\b/i, what: "reply in a customer support thread" },
    { re: /\b(?:whatsapp|telegram|messenger)[_.]?(?:send|api|client)\b/i, what: "message sent over a consumer messaging platform" },
    { re: /\b(?:elevenlabs|playht|text[_-]?to[_-]?speech|tts)\b/i, what: "synthetic voice played to a person" },
];
/* ═══════════════════════════════ 2 — identification present ═══ */
/**
 * Text or configuration that identifies the sender as an AI.
 *
 * Broad on purpose. The obligation is to inform, and teams word that a hundred
 * different ways — "sent by an automated assistant", `isBot: true`, an
 * `ai_disclosure` field. A narrow matcher here would produce false accusations
 * against teams that did the work, which is the costliest error this check can
 * make.
 */
// `[\s_-]?` throughout rather than `[_-]?`. These rules run against prose — email
// templates, system prompts, brand guidelines — as well as identifiers, and a
// separator class that excluded the space matched `automated_assistant` while
// missing "an automated assistant". Every miss of that kind is a false accusation
// against a team that did disclose, which is the costliest error this check makes.
const AI_DISCLOSURE = /\b(?:ai[\s_-]?disclosure|ai[\s_-]?generated|generated[\s_-]?by[\s_-]?(?:an?[\s_-]?)?(?:ai|automated)|is[\s_-]?bot|isBot|bot[\s_-]?label|automated[\s_-]?(?:assistant|agent|message|reply|response)|ai[\s_-]?assistant|powered[\s_-]?by[\s_-]?ai|this[\s_-]?is[\s_-]?an?[\s_-]?ai|X-AI-Generated)\b/i;
/** Prose disclosure as it appears in a template or a system prompt. */
const AI_DISCLOSURE_PROSE = /\b(?:I['’]?m|I am|this is)\s+(?:an?\s+)?(?:AI|A\.I\.|artificial intelligence|automated|virtual)\b|\byou(?:'| a)?re (?:chatting|speaking|talking) (?:with|to) an? (?:AI|bot|automated)\b|\bsent by an? (?:AI|automated|bot)\b/i;
/* ══════════════════════ 3 — identification actively removed ═══ */
/**
 * Configuration or code that suppresses the disclosure.
 *
 * Absent disclosure is an oversight. Removed disclosure is a decision, and it is
 * the one a regulator would treat as aggravating rather than mitigating. Reported
 * separately and always hard.
 */
const DISCLOSURE_SUPPRESSED = [
    // `\w*` tails throughout: real identifiers are `stripAiDisclosure`, not `strip_ai_disclosure`.
    { re: /(?:hide|suppress|strip|remove|disable|omit)[_.]?(?:ai)?[_.]?(?:disclosure|disclaimer|bot[_.]?label|watermark|signature)\w*/i, what: "code removes the AI disclosure before sending" },
    { re: keyValue("ai[_-]?disclosure|show[_.]?bot[_.]?label|bot[_.]?label|disclose[_.]?ai", "false|0|off|none"), what: "AI disclosure switched off in configuration" },
    { re: /\b(?:appear|pretend|pose|present|sound|seem)[\s_.]?(?:as|to\s+be)[\s_.]?(?:as\s+)?(?:human|a\s+human|a\s+person|real|a\s+real\s+person)\b/i, // Wording note: a rule's own label must avoid the words the rule matches.
        // String literals are deliberately NOT blanked in this module — a JSON
        // config value is the evidence — so a description written in the trigger
        // phrase makes the module report itself. That is what happened here.
        what: "configured to impersonate a person instead of identifying as an agent" },
    { re: keyValue("human[_.]?like[_.]?persona|pretend[_.]?human|hide[_.]?ai", "true|1|yes"), // Wording note: a rule's own label must avoid the words the rule matches.
        // String literals are deliberately NOT blanked in this module — a JSON
        // config value is the evidence — so a description written in the trigger
        // phrase makes the module report itself. That is what happened here.
        what: "configured to impersonate a person instead of identifying as an agent" },
    { re: /\b(?:do\s+not|don'?t|never)\s+(?:say|mention|reveal|disclose|admit|acknowledge)\s+(?:that\s+)?(?:you|this|it)\s*(?:are|is|'re)?\s*(?:an?\s+)?(?:AI|A\.I\.|bot|automated|assistant|machine)/i, what: "the agent is instructed not to reveal that it is an AI" },
];
/* ═══════════════════ 4 — synthetic media and its marking ═══ */
/** Generation of synthetic media, which Art. 50(2) requires be marked. */
const SYNTHETIC_MEDIA = [
    { re: /\b(?:dall[_-]?e|stable[_-]?diffusion|midjourney|imagen|flux|images?\.generate)\b/i, what: "synthetic image generation" },
    { re: /\b(?:elevenlabs|playht|voice[_.]?clone|speech[_.]?synthesis|audio\.speech)\b/i, what: "synthetic audio generation" },
    { re: /\b(?:sora|runway|pika|video[_.]?generat\w*)\b/i, what: "synthetic video generation" },
];
/** Provenance marking that satisfies the machine-readable requirement. */
// No trailing `\b`: the real call site is `attachC2PAManifest(img)`, where the
// term is embedded in a camelCase identifier and a word boundary never fires.
const PROVENANCE_MARKING = /(?:c2pa|content[_-]?credentials?|xmp|iptc|provenance|watermark|synthid|steganograph|exif)\w*/i;
/* ═══════════════════════════════════════════════════ entry ═══ */
export function scanDisclosure(files) {
    const findings = [];
    const live = files.filter((f) => !f.isTestOrFixture);
    // Suppression is per-file and always reported, wherever it appears.
    for (const f of live) {
        for (const rule of DISCLOSURE_SUPPRESSED) {
            const line = findLine(f.text, rule.re);
            if (line) {
                findings.push({
                    file: f.rel,
                    line,
                    article: "Art. 50(1)",
                    detail: `${rule.what} — removing an identification is a decision, not an omission`,
                    severity: "hard",
                });
                break;
            }
        }
    }
    // Presence of identification is a property of the repository, not of one file:
    // a disclosure defined in a template module discharges the obligation for every
    // sender that uses it. Asking the question per-file would fail every codebase
    // that factored the disclosure out, which is the well-built ones.
    const declared = existsInTree(files, AI_DISCLOSURE).found || existsInTree(files, AI_DISCLOSURE_PROSE).found;
    if (!declared) {
        for (const f of live.filter((x) => x.isCode || x.isConfig)) {
            for (const rule of HUMAN_CHANNELS) {
                const line = findLine(f.text, rule.re);
                if (line) {
                    findings.push({
                        file: f.rel,
                        line,
                        article: "Art. 50(1)",
                        detail: `${rule.what}, and no AI identification was found anywhere in this repository — ` +
                            `a person on the other end has not been told they are dealing with an agent`,
                        severity: "hard",
                    });
                    break;
                }
            }
        }
    }
    // Synthetic media without provenance marking.
    const marked = existsInTree(files, PROVENANCE_MARKING).found;
    if (!marked) {
        for (const f of live.filter((x) => x.isCode)) {
            for (const rule of SYNTHETIC_MEDIA) {
                const line = findLine(f.text, rule.re);
                if (line) {
                    findings.push({
                        file: f.rel,
                        line,
                        article: "Art. 50(2)",
                        detail: `${rule.what} with no machine-readable provenance marking (C2PA, Content Credentials, ` +
                            `or an embedded watermark) found in this repository`,
                        // Soft: the marking deadline for systems already on the market is
                        // 2 December 2026, and marking is often applied by the generating
                        // provider rather than by this code. Reported, not blocking.
                        severity: "soft",
                    });
                    break;
                }
            }
        }
    }
    return findings;
}
export function runDisclosureChecks(root) {
    const files = scanTree(root);
    if (files.length === 0) {
        return [{
                id: "regulatory.disclosure",
                title: "AI transparency (EU AI Act Art. 50)",
                status: "skip",
                detail: "No readable source files — nothing to assess",
                evidence: { scanned: 0, frameworks: FRAMEWORK_REFS },
            }];
    }
    const findings = scanDisclosure(files);
    const hard = findings.filter((f) => f.severity === "hard");
    const soft = findings.filter((f) => f.severity === "soft");
    // No human-facing channel at all: the obligation is not engaged. Reported as a
    // skip rather than a pass, because passing a check that never ran is the
    // vacuous verdict this project has already been caught emitting once.
    const hasChannel = files.some((f) => !f.isTestOrFixture &&
        (f.isCode || f.isConfig) &&
        HUMAN_CHANNELS.some((r) => matchesInCode(f.text, r.re)));
    const hasMedia = files.some((f) => !f.isTestOrFixture && f.isCode && SYNTHETIC_MEDIA.some((r) => matchesInCode(f.text, r.re)));
    if (!hasChannel && !hasMedia && findings.length === 0) {
        return [{
                id: "regulatory.disclosure",
                title: "AI transparency (EU AI Act Art. 50)",
                status: "skip",
                detail: `Scanned ${files.length} file(s) — this system does not open a channel to a natural person ` +
                    `or generate synthetic media, so Art. 50 transparency duties are not engaged`,
                evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    if (hard.length > 0) {
        return [{
                id: "regulatory.disclosure",
                title: "AI transparency (EU AI Act Art. 50)",
                status: "fail",
                detail: `${hard.length} transparency finding(s) — people reached by this system may not have been ` +
                    `told they are dealing with an AI. ` +
                    hard.slice(0, 3).map(renderFinding).join("; ") +
                    (hard.length > 3 ? ` (+${hard.length - 3} more)` : ""),
                evidence: {
                    hard: hard.slice(0, 20),
                    soft: soft.slice(0, 10),
                    scanned: files.length,
                    applicable_since: "2026-08-02",
                    frameworks: FRAMEWORK_REFS,
                },
            }];
    }
    if (soft.length > 0) {
        return [{
                id: "regulatory.disclosure",
                title: "AI transparency (EU AI Act Art. 50)",
                status: "warn",
                detail: `${soft.length} synthetic-media finding(s) with no provenance marking found. ` +
                    soft.slice(0, 2).map(renderFinding).join("; ") +
                    `. Machine-readable marking is required from 2 December 2026 for systems already on the market.`,
                evidence: { soft: soft.slice(0, 20), scanned: files.length, frameworks: FRAMEWORK_REFS },
            }];
    }
    return [{
            id: "regulatory.disclosure",
            title: "AI transparency (EU AI Act Art. 50)",
            status: "pass",
            detail: `Scanned ${files.length} file(s) — AI identification is present for the human-facing channels ` +
                `this system opens, and nothing suppresses it`,
            evidence: { scanned: files.length, frameworks: FRAMEWORK_REFS },
        }];
}
