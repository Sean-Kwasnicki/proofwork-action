export function summarize(checks) {
    const summary = { passed: 0, failed: 0, warned: 0, skipped: 0 };
    for (const c of checks) {
        if (c.status === "pass")
            summary.passed += 1;
        else if (c.status === "fail")
            summary.failed += 1;
        else if (c.status === "warn")
            summary.warned += 1;
        else
            summary.skipped += 1;
    }
    return summary;
}
export function integrityScore(summary) {
    const raw = 100 - summary.failed * 35 - summary.warned * 8;
    return Math.max(0, Math.min(100, raw));
}
export function buildProof(repo, checks, timing, binding) {
    const summary = summarize(checks);
    const blockers = checks
        .filter((c) => c.status === "fail")
        .map((c) => `${c.id}: ${c.detail}`);
    const score = integrityScore(summary);
    return {
        schema_version: "0.1.0",
        issuer: "Proofwork",
        engine: "proofwork",
        created_at: new Date().toISOString(),
        ok: summary.failed === 0,
        repo,
        checks,
        summary,
        blockers,
        integrity_score: score,
        ...(timing ? { timing } : {}),
        ...(binding ? { binding } : {}),
    };
}
