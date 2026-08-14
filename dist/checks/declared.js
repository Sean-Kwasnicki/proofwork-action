import fs from "node:fs";
import path from "node:path";
import { isTestPath } from "./testPaths.js";
import { scanForDelegatedAuthority, walkCode } from "./delegatedAuthority.js";
/**
 * Declared capabilities — what the operator says the agent can do, checked
 * against what its code can actually do.
 *
 * ## Why a manifest at all
 *
 * Everything else in this gate reads code and infers capability. That is the
 * right primary source — code is what runs — but inference alone cannot answer
 * the question a buyer is really asking, which is not "does this move money?" but
 * "does this do anything its owner did not tell me about?".
 *
 * A manifest turns an unbounded question into a comparable one. The operator
 * states the consequential surfaces; the gate reads the code; the two are
 * compared. Both directions of mismatch are findings, and they are different
 * findings:
 *
 *   - **Code does what the manifest omits.** This is the serious one, and it is
 *     classed as misrepresentation rather than as a missing control. Whoever read
 *     the manifest was told something untrue about what the agent can reach, and
 *     every downstream decision that relied on it — a review, an approval, an
 *     insurance answer — was made on that basis.
 *
 *   - **The manifest declares what the gate could not examine.** This is not a
 *     failure and must not be scored as one. It is a *limit on the claim*: the
 *     surface is recorded as NOT EXAMINED and the run cannot report a full clear.
 *
 * ## The asymmetry that matters
 *
 * An undeclared surface is worse than an undeclared *and* unexamined one, because
 * silence plus a clean report reads as "nothing here". Recording NOT EXAMINED
 * costs the operator nothing except the ability to claim something we did not
 * check — which they never had honestly.
 *
 * ## What this does not do
 *
 * It does not verify that a declared capability is *implemented well*. Declaring
 * `money: true` and passing this check means the declaration matches reality, not
 * that the money path is safe — that is what `delegated_authority`,
 * `record_keeping`, and the rest are for. A manifest is a statement of scope, and
 * this check tests whether the statement is true.
 */
/** Filenames accepted, in preference order. */
const MANIFEST_NAMES = ["proofwork.agent.json", "AGENT.capabilities.json"];
const SURFACES = [
    { key: "money", label: "moves money", declare: `"money": true` },
    { key: "refunds", label: "moves money out of the account", declare: `"refunds": true` },
    {
        key: "people_decisions",
        label: "makes decisions about people",
        declare: `"people_decisions": true`,
    },
];
/**
 * Read JSON written by a human on any platform.
 *
 * The byte-order mark is stripped because `JSON.parse` throws on it, and on
 * Windows a BOM is what you get by default from PowerShell's `Set-Content
 * -Encoding utf8`, from Notepad, and from several editors. Without this, an
 * operator who writes a perfectly correct manifest in the most obvious way is
 * told their declaration is malformed — on their first run, in the intake path
 * built specifically for people who are not already using the gate.
 *
 * It is not the operator's job to know that three invisible bytes at the front of
 * their file are the problem.
 */
function readJsonFile(abs) {
    return JSON.parse(fs.readFileSync(abs, "utf8").replace(/^﻿/, ""));
}
export function findManifest(root) {
    for (const name of MANIFEST_NAMES) {
        const abs = path.join(root, name);
        if (!fs.existsSync(abs))
            continue;
        try {
            return { file: name, manifest: readJsonFile(abs) };
        }
        catch {
            // A malformed manifest is reported by the caller as a finding rather than
            // silently treated as absent — "I could not read your declaration" and
            // "you made none" are different situations for the operator.
            return { file: name, manifest: {} };
        }
    }
    return null;
}
/** Does the manifest parse? Distinguished from absent, above. */
function manifestIsReadable(root, file) {
    try {
        readJsonFile(path.join(root, file));
        return true;
    }
    catch {
        return false;
    }
}
/**
 * What the code actually reaches.
 *
 * Reuses the authority scanner rather than growing a second set of money
 * patterns. Two detectors for one concept is how the enforcement half and the
 * detection half of `delegated_authority` drifted apart, and the fix there was to
 * have one source of truth. Repeating the mistake here would be worse, because
 * this check's whole purpose is to compare two descriptions of the same thing.
 */
export function detectSurfaces(root) {
    const out = {
        money: { found: false, where: [] },
        refunds: { found: false, where: [] },
        people_decisions: { found: false, where: [] },
    };
    /**
     * Executable source only — not prose, not config, not manifests.
     *
     * `delegated_authority` reads config and prompt files too, and is right to: a
     * threshold written in `AGENTS.md` is a real declaration. This check asks the
     * opposite question — what the code *does* — and for that, prose is noise.
     *
     * The distinction is not academic. Run against a corpus agent, the first draft
     * cited `EXPECTED.json` as a place the agent moves money, because that file
     * describes the agent in English. Applied to a customer, a README saying "this
     * service charges the customer monthly" would have failed an honest operator
     * for not declaring a capability their code does not have — a false accusation
     * produced by reading documentation as an implementation.
     */
    const files = walkCode(root).filter((rel) => !isTestPath(rel) && /\.[cm]?[jt]sx?$|\.py$|\.go$|\.rb$|\.java$|\.cs$/i.test(rel));
    for (const rel of files) {
        let text;
        try {
            text = fs.readFileSync(path.join(root, rel), "utf8");
        }
        catch {
            continue;
        }
        for (const f of scanForDelegatedAuthority(rel, text)) {
            if (f.kind === "unbounded_spend" && !out.money.where.includes(rel)) {
                out.money.found = true;
                out.money.where.push(rel);
            }
            if (f.kind === "fund_extraction" && !out.refunds.where.includes(rel)) {
                out.refunds.found = true;
                out.refunds.where.push(rel);
                // Extraction is a kind of money movement. Declaring only `refunds` and
                // not `money` should not read as an undeclared money surface.
                out.money.found = true;
                if (!out.money.where.includes(rel))
                    out.money.where.push(rel);
            }
        }
        if (PEOPLE_DECISION.test(text) && !out.people_decisions.where.includes(rel)) {
            out.people_decisions.found = true;
            out.people_decisions.where.push(rel);
        }
    }
    return out;
}
/**
 * Decisions with a person on the other end.
 *
 * Kept narrow on purpose. A broad match here would flag any code containing the
 * word "approve", and a check that fires on ordinary vocabulary teaches people to
 * declare everything, which destroys the signal the manifest exists to carry.
 */
const PEOPLE_DECISION = /\b(?:credit[_.]?(?:decision|limit|score)|underwrit\w*|loan[_.]?(?:decision|approval)|\w*(?:applicant|candidate)\w*)\b|\b(?:approve|deny|reject|decline)[_.]?(?:application|applicant|candidate|claim|loan|credit)\w*/i;
const FRAMEWORK_REFS = {
    iso42001: ["A.5.2 AI System Impact Assessment", "A.6.2.2 AI System Requirements"],
    nist: ["GOVERN 1.2", "MAP 2.1"],
    eu: ["Art. 11 Technical Documentation"],
};
export function runDeclaredCapabilityChecks(root, opts = {}) {
    const found = findManifest(root);
    if (!found) {
        /**
         * No manifest.
         *
         * A skip, not a failure. Requiring one would break every repository already
         * using the gate in CI, and the code-reading checks still run in full — an
         * agent without a manifest is examined exactly as before.
         *
         * The wording is deliberately different for bundle intake, where a manifest
         * carries more weight: with no git history there is less context around the
         * code, so what the operator says about it is the main thing distinguishing a
         * complete export from a partial one.
         */
        return [
            {
                id: "agent_security.declared_capabilities",
                title: "Declared capabilities",
                status: "skip",
                detail: opts.bundle
                    ? "No capability manifest in this bundle. The code was examined in full, but nothing " +
                        "states what the agent is supposed to reach — so an omitted surface cannot be " +
                        "distinguished from an absent one. Add proofwork.agent.json."
                    : "No capability manifest — add proofwork.agent.json to declare what this agent can " +
                        "reach, and the gate will check the declaration against the code.",
                evidence: { manifest: null, frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    if (!manifestIsReadable(root, found.file)) {
        return [
            {
                id: "agent_security.declared_capabilities",
                title: "Declared capabilities",
                status: "fail",
                detail: `${found.file} is not valid JSON, so the declaration could not be read. A manifest that ` +
                    `cannot be parsed is worse than none: tooling that reads it will see an empty object and ` +
                    `conclude the agent declares no consequential surfaces at all.`,
                evidence: { manifest: found.file, parse_error: true, frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    const declared = found.manifest.capabilities ?? {};
    const detected = detectSurfaces(root);
    const undeclared = [];
    const notExamined = [];
    for (const spec of SURFACES) {
        const isDeclared = declared[spec.key] === true;
        const isDetected = detected[spec.key].found;
        if (isDetected && !isDeclared) {
            undeclared.push({
                surface: spec.key,
                label: spec.label,
                where: detected[spec.key].where.slice(0, 5),
                declare: spec.declare,
            });
        }
        if (isDeclared && !isDetected) {
            // Declared but nothing in the code matched. Not a lie and not a pass — the
            // operator says the surface exists somewhere the gate could not see it, so
            // the claim is bounded rather than cleared.
            notExamined.push({ surface: spec.key, label: spec.label });
        }
    }
    if (undeclared.length > 0) {
        const lines = undeclared.map((u) => `${u.label} — ${u.where.join(", ")} (declare ${u.declare})`);
        return [
            {
                id: "agent_security.declared_capabilities",
                title: "Declared capabilities",
                status: "fail",
                detail: `This agent reaches ${undeclared.length} consequential surface(s) that ${found.file} does ` +
                    `not declare: ${lines.join("; ")}. ` +
                    `The manifest is what a reviewer reads instead of the source, so an omission here is not ` +
                    `a missing control — it is a false description of scope, and every decision made from it ` +
                    `was made on the wrong facts. Declare the surface, or remove the capability from the code.`,
                evidence: {
                    manifest: found.file,
                    undeclared,
                    not_examined: notExamined,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    if (notExamined.length > 0) {
        return [
            {
                id: "agent_security.declared_capabilities",
                title: "Declared capabilities",
                status: "warn",
                detail: `${found.file} declares ${notExamined.map((n) => n.label).join(", ")}, and the gate found ` +
                    `no code implementing that surface. Nothing is wrong with the declaration — it is recorded ` +
                    `as NOT EXAMINED, and this run cannot report a full clear on a surface it never saw. ` +
                    `If the capability lives in a service this bundle does not contain, that is expected; ` +
                    `include it, or read the certificate as covering only what is here.`,
                evidence: {
                    manifest: found.file,
                    not_examined: notExamined,
                    declared,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    const declaredList = SURFACES.filter((s) => declared[s.key] === true).map((s) => s.label);
    return [
        {
            id: "agent_security.declared_capabilities",
            title: "Declared capabilities",
            status: "pass",
            detail: declaredList.length > 0
                ? `${found.file} declares ${declaredList.join(", ")}, and the code matches — every ` +
                    `consequential surface the gate can detect is declared, and every declared surface was ` +
                    `found and examined.`
                : `${found.file} declares no consequential surfaces, and the gate found none. The code ` +
                    `does not reach money or decisions about people.`,
            evidence: { manifest: found.file, declared, detected, frameworks: FRAMEWORK_REFS },
        },
    ];
}
