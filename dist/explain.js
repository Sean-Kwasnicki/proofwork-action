/** Plain-English PASS/FAIL for humans and agents — no jargon dump. */
export function explainProof(proof) {
    const lines = [];
    if (proof.ok) {
        lines.push("RESULT: PASS");
        lines.push("");
        lines.push("What this means:");
        lines.push("- Proofwork’s integrity checks did not find fake-green tests, reintroduced deleted code, a burn loop, or grader tampering.");
        lines.push("- The agent may claim done for this gate — humans should still do normal code review.");
        lines.push("- PASS is not a warranty that the product is bug-free. It means these integrity traps did not fire.");
        lines.push("");
        lines.push("Next: run `proofwork certify` / `proofwork share` and paste the card on the PR.");
    }
    else {
        lines.push("RESULT: FAIL");
        lines.push("");
        lines.push("What this means:");
        lines.push("- Do NOT merge on the agent’s word that “tests are green.”");
        lines.push("- Something in the integrity gate blocked completion. Fix blockers, then re-run.");
        lines.push("");
        lines.push("Blockers:");
        for (const b of proof.blockers.slice(0, 8))
            lines.push(`- ${b}`);
        if (!proof.blockers.length)
            lines.push("- (see proofwork doctor)");
        lines.push("");
        lines.push("Common fixes:");
        lines.push("- fake_green → remove skip/.only/empty/hollow asserts; don’t mock the unit under test");
        lines.push("- reintroduction → don’t restore deleted risky logic; or fingerprints reset only if store is wrong");
        lines.push("- spend_loop → stop repeating the same failing command; clear ledger after a real fix");
        lines.push("- grader → do not edit workflows/hooks/config to force green; human must approve judge changes");
        lines.push("");
        lines.push("Next: `proofwork doctor` then `proofwork status` until PASS.");
    }
    if (typeof proof.integrity_score === "number") {
        lines.push("");
        lines.push(`Integrity score: ${proof.integrity_score}/100 (fails hurt more than warns).`);
    }
    return `${lines.join("\n")}\n`;
}
