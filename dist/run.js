import { inspectRepo, runReadinessChecks } from "./checks/readiness.js";
import { runReintroductionChecks } from "./checks/reintroduction.js";
import { runFakeGreenChecks } from "./checks/fakeGreen.js";
import { runVerificationChecks } from "./checks/verification.js";
import { runDeclaredCapabilityChecks } from "./checks/declared.js";
import { isProtectedCheckId, runGraderIntegrityChecks } from "./checks/graderIntegrity.js";
import { runSpendLoopChecks } from "./checks/spendLoop.js";
import { runAiGovernanceChecks } from "./checks/aiGovernance.js";
import { runAgentSecurityChecks } from "./checks/agentSecurity.js";
import { runAgentAutonomyChecks } from "./checks/agentAutonomy.js";
import { runAgentHijackChecks } from "./checks/agentHijack.js";
import { runDelegatedAuthorityChecks } from "./checks/delegatedAuthority.js";
import { runDisclosureChecks } from "./checks/regulatory/disclosure.js";
import { runRecordKeepingChecks } from "./checks/regulatory/recordKeeping.js";
import { runAutomatedDecisionChecks } from "./checks/regulatory/automatedDecision.js";
import { runWorkmanshipChecks } from "./checks/workmanship.js";
import { runChangeTestBindChecks } from "./checks/changeTestBind.js";
import { loadConfig } from "./config.js";
import { buildGitContext } from "./gitContext.js";
import { attachStory } from "./report.js";
import { computeTreeBinding } from "./binding.js";
import { computeBundleBinding } from "./bundle.js";
import { buildProof } from "./types.js";
export function runProof(opts) {
    const t0 = performance.now();
    const config = loadConfig(opts.root);
    const strictAuth = opts.strictAuth ?? config.strictAuth;
    const strict = opts.strict ?? config.strictIntegrity ?? false;
    const fast = opts.fast ?? process.env.PROOFWORK_FAST === "1";
    /**
     * `skipChecks` cannot remove a protected check. Ever, and regardless of when
     * it was written.
     *
     * This was previously enforced by *detection*: `integrity.grader` reported a
     * config edit that added a protected namespace to `skipChecks`. A red-team
     * engagement showed why that was the wrong layer — the detector only inspects
     * configuration that appears in the current diff, so a repository that shipped
     * `skipChecks` in its very first commit was never examined. The gate then
     * filtered out most of its own checks and reported a clean result on an agent
     * that could drain its owner's card.
     *
     * Detection asks "did someone just weaken the gate?", which a repository born
     * weakened never triggers. Enforcement asks "is this check allowed to be off?",
     * which has the same answer at every commit. The request is refused here, and
     * separately reported below so the attempt is visible rather than silently
     * ignored.
     */
    const requestedSkips = config.skipChecks ?? [];
    const refusedSkips = requestedSkips.filter((id) => isProtectedCheckId(id));
    const skip = new Set(requestedSkips.filter((id) => !isProtectedCheckId(id)));
    const git = buildGitContext(opts.root);
    const repo = inspectRepo(opts.root, git);
    let checks = [
        ...runReadinessChecks(opts.root, { strictAuth, fast, git, bundle: opts.bundle ?? false }),
    ];
    if (!opts.readinessOnly) {
        // Shared git context — no duplicate git execs across integrity checks
        checks.push(...runGraderIntegrityChecks(opts.root, git));
        checks.push(...runReintroductionChecks(opts.root, git));
        // Does a verification mechanism exist at all? Runs before the checks that
        // inspect test quality, because "no tests" is the evasion those cannot see.
        checks.push(...runVerificationChecks(opts.root));
        // Compare what the operator declared against what the code reaches. Runs
        // alongside the code-reading checks rather than instead of them — a manifest
        // bounds the claim, it never substitutes for reading the source.
        checks.push(...runDeclaredCapabilityChecks(opts.root, { bundle: opts.bundle ?? false }));
        checks.push(...runFakeGreenChecks(opts.root, git, { strict }));
        // Work that runs but does not do what it appears to: hollow tests, discarded
        // errors, unfinished markers. The failures an agent commits without meaning to.
        checks.push(...runWorkmanshipChecks(opts.root, git, { strict }));
        checks.push(...runChangeTestBindChecks(opts.root, git));
        checks.push(...runSpendLoopChecks(opts.root, {
            maxIdenticalFailures: config.maxIdenticalFailures,
        }));
        // Governance evidence. Skips itself entirely on repos with no AI dependencies,
        // so non-AI projects pay nothing for it.
        checks.push(...runAiGovernanceChecks(opts.root));
        // Can this agent be turned against its owner? Static half only — live probing
        // needs the target owner's written authorization and belongs in an engagement.
        checks.push(...runAgentSecurityChecks(opts.root));
        // What can the agent do on its own, and did anyone agree to it?
        checks.push(...runAgentAutonomyChecks(opts.root));
        // Can this agent be used to take control of a different agent? The question
        // that only exists once agents talk to each other — OWASP ASI 2026.
        checks.push(...runAgentHijackChecks(opts.root));
        // Whose authority is being spent? Autonomy is fine; acting as the owner
        // without a boundary the owner set is not.
        checks.push(...runDelegatedAuthorityChecks(opts.root));
        // Regulatory obligations that bind autonomous agents specifically. Each
        // skips itself when the duty is not engaged, so a project the rule does not
        // reach pays nothing for it.
        //
        // Art. 50 transparency became applicable on 2 August 2026 — this is a live
        // obligation, not a forthcoming one.
        checks.push(...runDisclosureChecks(opts.root));
        checks.push(...runRecordKeepingChecks(opts.root));
        checks.push(...runAutomatedDecisionChecks(opts.root));
    }
    if (skip.size) {
        checks = checks.filter((c) => !skip.has(c.id));
    }
    // A refused skip is reported as a failure in its own right. Silently ignoring
    // the request would leave the operator believing a check was disabled while it
    // ran, and leave an attempt to disable the gate unrecorded — the attempt is
    // itself the finding.
    if (refusedSkips.length > 0) {
        checks.push({
            id: "integrity.grader_bypass",
            title: "Attempt to disable protected checks",
            status: "fail",
            detail: `Configuration asks to skip ${refusedSkips.length} protected check(s): ` +
                `${refusedSkips.join(", ")}. These cannot be disabled and were run anyway. ` +
                `Namespaces that can fail a run are not configurable, whether the request was ` +
                `added today or present in the first commit.`,
            evidence: { refused: refusedSkips, requested: requestedSkips },
        });
    }
    // Bind the proof to the state it describes, so a consumer can prove this proof
    // belongs to the code in front of it rather than to some other commit.
    //
    // A bundle gets a content digest instead of a commit. Both pin one exact state,
    // which is what binding is for; only a commit is additionally a name in a
    // history somebody else can fetch, and that difference is carried in the
    // binding's `algo` rather than smoothed over.
    const binding = opts.bundle ? computeBundleBinding(opts.root) : computeTreeBinding(opts.root);
    const total_ms = Math.round(performance.now() - t0);
    let proof = buildProof(repo, checks, {
        total_ms,
        git_ms: git.git_ms,
        checks_ms: Math.max(0, total_ms - git.git_ms),
    }, binding);
    /**
     * `failOnWarn` blocks on warnings — but not on advisory ones.
     *
     * A check marked advisory is one whose warning is an observation rather than
     * evidence that the work is not what it claims to be. `--strict` already
     * exempts those; counting them here meant the two rules contradicted each
     * other, and a team that opted into the stricter setting could be blocked from
     * merging by a note we describe as advice.
     *
     * The finding is still reported and still costs score. It just stops being the
     * reason a build is red.
     */
    const blockingWarnings = proof.checks.filter((c) => c.status === "warn" && !c.advisory).length;
    if (config.failOnWarn && blockingWarnings > 0 && proof.ok) {
        proof = {
            ...proof,
            ok: false,
            blockers: [
                ...proof.blockers,
                `failOnWarn: ${blockingWarnings} warning(s) present`,
            ],
        };
    }
    return attachStory(proof);
}
