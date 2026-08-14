import { remediationsForProof } from "./remediation.js";
/** Ultra-short agent brief — minimize tokens / latency in hooks and MCP. */
export function proofToAgentBrief(proof) {
    const t = proof.timing ? `${proof.timing.total_ms}ms` : "?ms";
    const score = typeof proof.integrity_score === "number" ? ` score=${proof.integrity_score}` : "";
    const head = `Proofwork ${proof.ok ? "PASS" : "FAIL"} (${t})${score} pass=${proof.summary.passed} fail=${proof.summary.failed} warn=${proof.summary.warned}`;
    if (proof.ok) {
        return `${head}\nSTORY: Clean gate — agent may claim done.`;
    }
    const blockers = proof.blockers.slice(0, 5).join("; ");
    const story = proof.story ?? proofToAgentStory(proof);
    return `${head}\nBLOCKERS: ${blockers || "(see latest.json)"}\nSTORY: ${story}`;
}
/** Narrative that makes FAIL feel like a near-miss save — wow for agents/humans. */
export function proofToAgentStory(proof) {
    if (proof.ok) {
        return `Integrity ${proof.integrity_score ?? 100}/100. No fake-green, zombie reintro, or burn-loop tripwire fired.`;
    }
    const parts = [];
    parts.push(`Caught before merge (integrity ${proof.integrity_score ?? 0}/100). Without Proofwork this likely ships as "green."`);
    for (const c of proof.checks) {
        if (c.status !== "fail")
            continue;
        if (c.id === "integrity.fake_green") {
            const hard = Array.isArray(c.evidence?.hard) ? c.evidence.hard : [];
            const tip = hard[0]
                ? `${hard[0].id ?? "pattern"} in ${hard[0].file ?? "test"}:${hard[0].line ?? "?"}`
                : c.detail;
            parts.push(`Fake-green: ${tip}. Remove skip/.only/empty/tautology — don't silence the suite.`);
        }
        else if (c.id === "integrity.reintroduction") {
            const hits = Array.isArray(c.evidence?.hits) ? c.evidence.hits : [];
            const sample = hits[0]?.sample ?? "deleted logic";
            parts.push(`Zombie code returned: ${sample}. That delete was load-bearing — don't resurrect it.`);
        }
        else if (c.id === "integrity.spend_loop") {
            parts.push(`Burn loop: identical failure repeated. Stop retrying the same command — change approach or ask the human.`);
        }
        else if (c.id === "integrity.grader") {
            parts.push(`Grader tamper: agent edited the judge (workflow/hooks/config). Human approval required — revert and fix the product code instead.`);
        }
        else {
            parts.push(`${c.id}: ${c.detail}`);
        }
    }
    parts.push("Do not claim done until proofwork status PASSes.");
    return parts.join(" ");
}
export function attachStory(proof) {
    return { ...proof, story: proofToAgentStory(proof) };
}
export function proofToMarkdown(proof) {
    const lines = [];
    lines.push(`## Proofwork ${proof.ok ? "✅ PASS" : "❌ FAIL"}`);
    lines.push("");
    if (typeof proof.integrity_score === "number") {
        lines.push(`- Integrity score: \`${proof.integrity_score}/100\``);
    }
    lines.push(`- Schema: \`${proof.schema_version}\``);
    lines.push(`- Created: \`${proof.created_at}\``);
    lines.push(`- Summary: pass=${proof.summary.passed} fail=${proof.summary.failed} warn=${proof.summary.warned} skip=${proof.summary.skipped}`);
    if (proof.story) {
        lines.push("");
        lines.push(`> ${proof.story}`);
    }
    lines.push("");
    lines.push("| Status | Check | Detail |");
    lines.push("| --- | --- | --- |");
    for (const c of proof.checks) {
        const icon = c.status === "pass" ? "✅" : c.status === "fail" ? "❌" : c.status === "warn" ? "⚠️" : "⏭️";
        const detail = c.detail.replace(/\|/g, "\\|").replace(/\n/g, " ");
        lines.push(`| ${icon} ${c.status} | \`${c.id}\` | ${detail} |`);
    }
    if (proof.blockers.length) {
        lines.push("");
        lines.push("### Blockers");
        for (const b of proof.blockers)
            lines.push(`- ${b}`);
    }
    // Every failure this gate produces is one of a known set, so the fix ships with
    // the finding. A reader should never have to ask a model what to do next.
    const fixes = remediationsForProof(proof.checks);
    if (fixes.length) {
        lines.push("");
        lines.push("### How to fix");
        for (const { check, fix } of fixes) {
            lines.push("");
            lines.push(`#### ${check.title} \`${check.id}\``);
            lines.push("");
            lines.push(fix.summary);
            lines.push("");
            lines.push(`**Why it matters.** ${fix.why}`);
            lines.push("");
            fix.steps.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
            lines.push("");
            lines.push(`**Verify.** ${fix.verify}`);
            if (fix.reference)
                lines.push(`**Reference.** ${fix.reference}`);
        }
    }
    lines.push("");
    lines.push("_Independent Proof of Work for AI coding agents — not agent self-report._");
    return `${lines.join("\n")}\n`;
}
