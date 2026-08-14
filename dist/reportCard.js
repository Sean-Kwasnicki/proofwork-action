import { categoryOf as categoryOfCheck, scoreByCategory, scoreProof, } from "./scoring.js";
import { remediationFor } from "./remediation.js";
/**
 * Points allocated across the report card. Sums to 100 when every category
 * applies; renormalised below when some do not.
 */
export const CATEGORIES = [
    {
        id: "authority",
        name: "Authority & Consent",
        weight: 25,
        means: "The agent acts within authority someone actually granted it, and cannot be turned into an " +
            "instrument for something nobody approved.",
        rationale: "The heaviest section, because it is the only one whose worst outcome has no recoverable " +
            "version. Code can be reverted and disclosures corrected; money moved without consent stays " +
            "moved. A finding here caps the overall grade no matter how strong everything else is.",
    },
    {
        id: "build_integrity",
        name: "Build Integrity",
        weight: 20,
        means: "The work the agent reported as done was actually done, and the evidence for it has not been " +
            "altered.",
        rationale: "Weighted second because it defeats every control downstream of it. Once a report of success " +
            "is untrue, every process that trusted that report — review, release, audit — was operating " +
            "on a false premise, and the cost compounds silently.",
    },
    {
        id: "security",
        name: "Security Posture",
        weight: 18,
        means: "Credentials and capabilities are not reachable from anything an attacker can influence.",
        rationale: "Weighted on blast radius rather than likelihood. Most exposures are never exploited; the ones " +
            "that are tend to be total, because a credential in reach of an agent's context is a credential " +
            "in reach of anything that agent reads.",
    },
    {
        id: "regulatory",
        name: "Regulatory Conduct",
        weight: 17,
        means: "People affected by the agent were told it was an AI, what it did can be reconstructed, and " +
            "anyone it decided about can reach a human.",
        rationale: "Outranks workmanship despite being far rarer, because the loss lands on someone who never " +
            "chose to deal with this agent. The operator accepted the risk of deploying one; the person it " +
            "emailed or declined did not, and a scoring system that weighted by frequency would rank this " +
            "below a missing assertion.",
    },
    {
        id: "workmanship",
        name: "Workmanship",
        weight: 12,
        means: "The work is genuinely finished rather than finished-looking: tests assert, failures surface, " +
            "nothing unfinished shipped as complete.",
        rationale: "The most frequently lost points and deliberately not the heaviest. These are honest mistakes " +
            "with a recoverable version — the fix is a commit away and nobody outside the team is harmed " +
            "before it lands. Weighting the common thing hardest would make the grade a measure of tidiness.",
    },
    {
        id: "governance",
        name: "Governance Evidence",
        weight: 8,
        means: "What you have published about your AI supply chain matches what your code actually uses.",
        rationale: "The lightest enforcing section. Staleness here is real and worth reporting — it is what a " +
            "security questionnaire catches — but it is recoverable in an afternoon and harms nobody in the " +
            "interim.",
    },
    {
        id: "readiness",
        name: "Assessment Coverage",
        weight: 0,
        means: "How much of the agent's surface could actually be examined. This section carries no points of " +
            "its own; it caps the total.",
        rationale: "A repository that exposed little to the gate has not earned a high grade — it has avoided " +
            "examination. Rather than deduct for that, which would be indistinguishable from finding real " +
            "problems, coverage limits the ceiling and says so.",
    },
];
/** Which report-card section a check belongs to. */
export function categoryOf(checkId) {
    return categoryOfCheck(checkId) ?? "readiness";
}
/**
 * Pull `file:line` pairs out of a check's evidence.
 *
 * Evidence shapes differ per check — some carry `hard`/`soft` arrays, some
 * `capabilities`, some `unenforced_thresholds`. Rather than teach this function
 * every shape, it walks any array of objects that carry a `file`, which is the
 * one field every finding type already agrees on.
 */
function locationsFrom(check, max = 6) {
    const out = [];
    const evidence = (check.evidence ?? {});
    for (const value of Object.values(evidence)) {
        if (!Array.isArray(value))
            continue;
        for (const item of value) {
            if (out.length >= max)
                return out;
            if (!item || typeof item !== "object")
                continue;
            const f = item;
            if (typeof f.file !== "string")
                continue;
            const where = typeof f.line === "number" ? `${f.file}:${f.line}` : f.file;
            const what = (typeof f.detail === "string" && f.detail) ||
                (typeof f.what === "string" && f.what) ||
                (typeof f.why === "string" && f.why) ||
                (typeof f.name === "string" && `\`${f.name}\``) ||
                "";
            if (!out.some((o) => o.where === where))
                out.push({ where, what: String(what).slice(0, 96) });
        }
    }
    return out;
}
const LETTER = [
    [97, "A+"], [93, "A"], [90, "A−"],
    [87, "B+"], [83, "B"], [80, "B−"],
    [77, "C+"], [73, "C"], [70, "C−"],
    [67, "D+"], [60, "D"], [0, "F"],
];
export function letterFor(pct) {
    return LETTER.find(([min]) => pct >= min)?.[1] ?? "F";
}
/**
 * How much of a category's allocation a set of findings costs.
 *
 * A blocking finding takes the whole section. That is deliberate: these
 * categories are not checklists where four of five is most of the way there.
 * "Mostly did not move money without asking" is not a partial success, and a
 * scoring model that awarded 80% of Authority & Consent for it would be
 * describing something that did not happen.
 *
 * Advisory findings scale, because uncertainty should reduce a grade without
 * dominating it — and because a section that dropped to zero on a warning would
 * teach people to suppress warnings, losing the signal entirely.
 */
export function buildReportCard(proof, subject = "This repository") {
    const score = scoreProof(proof);
    // Every number below comes from the engine. This module decides how sections
    // are *described*, never what they are worth — the period when it computed its
    // own totals is what produced three different scores for one run.
    const engine = scoreByCategory(proof.checks);
    const engineById = new Map(engine.categories.map((c) => [c.id, c]));
    const byCategory = new Map();
    for (const check of proof.checks) {
        const id = categoryOf(check.id);
        byCategory.set(id, [...(byCategory.get(id) ?? []), check]);
    }
    const enforcing = CATEGORIES.filter((c) => c.weight > 0);
    const categories = [];
    for (const def of enforcing) {
        const checks = byCategory.get(def.id) ?? [];
        const scored = engineById.get(def.id);
        const assessed = scored?.applies ?? false;
        const possible = scored?.possible ?? 0;
        if (!assessed) {
            categories.push({
                id: def.id,
                name: def.name,
                possible: 0,
                earned: 0,
                grade: "—",
                status: "not_assessed",
                means: def.means,
                rationale: def.rationale,
                findings: { blocking: 0, advisory: 0 },
                lost_because: [],
                locations: [],
                blockers: [],
            });
            continue;
        }
        const problems = checks.filter((c) => c.status === "fail" || c.status === "warn");
        const earned = scored?.earned ?? 0;
        const blocking = scored?.blocking ?? 0;
        const advisory = scored?.advisory ?? 0;
        // Customer-facing reasons come from remediation summaries, which are written
        // for the reader. The check's own detail string is not used here — it names
        // internals, and this surface must not.
        const lost_because = problems
            .map((c) => remediationFor(c)?.summary)
            .filter((s) => Boolean(s));
        const worst = problems.find((c) => c.status === "fail") ?? problems[0];
        const guide = worst ? remediationFor(worst) : undefined;
        /**
         * Every failing check in this category, each with the steps that clear it.
         *
         * The route to 100 used to carry one line per category, taken from the first
         * step of the worst finding's guide. For a money-out failure that line read
         * "switch to your own service credential" — advice that does not touch the
         * actual finding, which was that no ceiling or approval step exists anywhere.
         * A team could follow the whole of the printed remediation and fail again on
         * the identical check.
         *
         * The gap was structural rather than a wording problem. One category holds
         * several checks, one check has several independent ways to fail, and
         * collapsing all of that into one sentence meant most blockers were never
         * named. What a paying customer needs is every blocker, each with what
         * clears it.
         */
        const blockers = problems
            .filter((c) => c.status === "fail")
            .map((c) => {
            const g = remediationFor(c);
            return {
                id: c.id,
                title: g?.summary ?? c.title,
                steps: g?.steps ?? ["Review the findings listed for this check."],
            };
        });
        categories.push({
            id: def.id,
            name: def.name,
            possible,
            earned,
            grade: letterFor(possible > 0 ? (earned / possible) * 100 : 100),
            status: blocking > 0 ? "failed" : advisory > 0 ? "reduced" : "clear",
            means: def.means,
            rationale: def.rationale,
            findings: { blocking, advisory },
            lost_because: [...new Set(lost_because)],
            locations: problems.flatMap((c) => locationsFrom(c)).slice(0, 8),
            blockers,
            ...(guide ? { next_step: guide.steps[0] } : {}),
        });
    }
    const coverageCap = engine.coverageCap;
    const adjustments = [];
    if (score.severity_cap !== null) {
        adjustments.push({
            label: "Ceiling — severity of finding",
            effect: `≤ ${score.severity_cap}`,
            detail: "One finding in this run is serious enough to cap the grade on its own, independently of " +
                "how many other sections are clean. Sections do not average away a failure of this kind.",
        });
    }
    if (coverageCap < 100) {
        adjustments.push({
            label: `Ceiling — assessment coverage (${engine.examined}/${engine.considered})`,
            effect: `≤ ${coverageCap}`,
            detail: `${engine.considered - engine.examined} area(s) that apply to this repository could not be ` +
                `examined, so the ceiling is reduced — a surface that was not inspected has not been ` +
                `cleared. Sections that did not apply at all are excluded from the total instead, and do ` +
                `not affect this ceiling.`,
        });
    }
    /**
     * The headline is the engine's total — which is now the sum of the sections
     * above, then the ceilings.
     *
     * Both halves of that sentence matter. The customer will add up the column, so
     * it has to reach the headline; and the certificate, the CLI, and this card all
     * have to print the same figure, so it has to come from one place. Satisfying
     * only the first is how this project ended up with three totals for one run.
     */
    const overallEarned = score.final;
    const path_to_100 = categories
        .filter((c) => c.status === "failed" || c.status === "reduced")
        .map((c) => ({
        category: c.name,
        points: Math.round((c.possible - c.earned) * 10) / 10,
        action: c.next_step ?? "Review the findings listed for this section.",
        blockers: c.blockers,
    }))
        .sort((a, b) => b.points - a.points);
    return {
        subject,
        issued_at: new Date().toISOString(),
        overall: {
            earned: overallEarned,
            possible: 100,
            grade: letterFor(overallEarned),
            band: score.band,
        },
        categories,
        adjustments,
        path_to_100,
        not_assessed: categories.filter((c) => c.status === "not_assessed").map((c) => c.name),
    };
}
/* ─────────────────────────────────────────────────────────── rendering ─── */
const bar = (earned, possible, width = 18) => {
    if (possible === 0)
        return "─".repeat(width);
    const filled = Math.round((earned / possible) * width);
    return "█".repeat(filled) + "░".repeat(width - filled);
};
/** Render for a terminal. The same data drives the HTML certificate. */
export function renderReportCard(card) {
    const rule = "─".repeat(72);
    const out = [
        "",
        `  PROOFWORK REPORT CARD`,
        `  ${card.subject}`,
        `  ${rule}`,
        "",
        `  OVERALL   ${card.overall.grade.padEnd(4)} ${card.overall.earned}/100   ${card.overall.band.toUpperCase()}`,
        "",
        `  Sections below add up to this figure, then any ceiling is applied.`,
        `  Every step is shown so the total can be checked rather than believed.`,
        "",
        `  ${rule}`,
        "",
    ];
    for (const c of card.categories) {
        if (c.status === "not_assessed") {
            out.push(`  ${c.name.padEnd(22)} —    not assessed`);
            out.push(`  ${" ".repeat(22)} This did not apply here, so it is excluded from the total`);
            out.push(`  ${" ".repeat(22)} rather than awarded or deducted.`);
            out.push("");
            continue;
        }
        const score = `${c.earned}/${c.possible}`;
        out.push(`  ${c.name.padEnd(22)} ${c.grade.padEnd(3)} ${score.padStart(9)}  ${bar(c.earned, c.possible)}`);
        if (c.lost_because.length > 0) {
            for (const reason of c.lost_because)
                out.push(`  ${" ".repeat(22)} · ${reason}`);
        }
        // The locations, in the report itself. Previously the card said "open each
        // file:line" and contained none of them — a paying customer had to run
        // `check --json` to act on what they had just bought.
        if (c.locations.length > 0) {
            out.push("");
            for (const l of c.locations) {
                out.push(`  ${" ".repeat(22)} ${l.where}`);
                if (l.what)
                    out.push(`  ${" ".repeat(24)} ${l.what}`);
            }
        }
        out.push("");
    }
    if (card.adjustments.length > 0) {
        out.push(`  ${rule}`, "", "  ADJUSTMENTS", "");
        for (const a of card.adjustments) {
            out.push(`  ${a.label.padEnd(46)} ${a.effect}`);
            out.push(`    ${a.detail}`);
            out.push("");
        }
    }
    if (card.path_to_100.length > 0) {
        /**
         * The repair prompt, for the reader who does not write code.
         *
         * PATH TO 100 already contains everything needed to fix the run, and a
         * capable agent handed the whole card fixes every finding in one pass — that
         * was tested end to end and turned an F into a pass on the second run. What
         * was missing was the instruction to do it. Somebody who delegates their
         * coding has no reason to know that a report card is a thing you can paste.
         *
         * Placed immediately above PATH TO 100 so selecting from this heading to the
         * last step is one drag. Splitting them would mean explaining which parts to
         * copy, and an instruction that needs an instruction is not one.
         *
         * Shown only when something actually failed. `path_to_100` also carries
         * categories that merely lost advisory points, and telling someone to "fix
         * every finding" on a run with no findings to fix would teach them the block
         * is noise.
         */
        const hasBlockers = card.path_to_100.some((s) => s.blockers.length > 0);
        if (hasBlockers) {
            out.push(`  ${rule}`, "", "  GIVE THIS TO YOUR CODING AGENT", `  ${"─".repeat(32)}`, "", "  Copy from this line down to the end of PATH TO 100 and paste it into", "  your coding agent — Cursor, Claude Code, Copilot, whichever you use.", "", "  Fix EVERY finding in this Proofwork report in one pass.", "  Do not skip any PATH TO 100 item. Do not delete or weaken tests to pass.", "  Keep the file:line locations. Do not invent extra scope.", "  When done, tell the operator to run: proofwork check", "  Then: proofwork report", "", "  Deleting a failing test would clear the finding and lose the thing that", "  was protecting you. This gate is built to catch exactly that, so it will", "  come back as a worse result rather than a pass.", "");
        }
        out.push(`  ${rule}`, "", "  PATH TO 100", "");
        for (const step of card.path_to_100) {
            out.push(`  +${String(step.points).padStart(5)}  ${step.category}`);
            if (step.blockers.length === 0) {
                // Points lost to advisory findings rather than a blocking check.
                out.push(`         ${step.action}`);
                out.push("");
                continue;
            }
            // Every blocking check id, each with what clears it. Naming the id matters:
            // it is what the re-run will report, so a reader can tell which of several
            // failures a given instruction addresses.
            for (const b of step.blockers) {
                out.push("");
                out.push(`         ${b.id}`);
                out.push(`           ${b.title}`);
                for (const s of b.steps)
                    out.push(`           · ${s}`);
            }
            out.push("");
        }
    }
    else if (card.overall.earned >= 100) {
        out.push(`  ${rule}`, "", "  Nothing was lost. This is a perfect run.", "");
    }
    else {
        // Every section was clean and the total is still short, which means a ceiling
        // is doing the work. Saying "perfect run" here would be false in the one place
        // a customer is most likely to check the arithmetic — and the gap is
        // recoverable, so it belongs in the route to 100 rather than being glossed.
        out.push(`  ${rule}`, "", "  Every section that applied came back clean. The remaining points are held", `  by the ceiling above, not by a finding in your code — see ADJUSTMENTS for`, "  what to expose so the ceiling lifts.", "");
    }
    if (card.not_assessed.length > 0) {
        out.push(`  Not assessed (did not apply, excluded from the total): ${card.not_assessed.join(", ")}`, "");
    }
    return out.join("\n");
}
