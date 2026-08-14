import fs from "node:fs";
import path from "node:path";
import { tryExec } from "../util/exec.js";
import { resolveBaseRef, isTrustedBaseSource } from "../binding.js";
/**
 * Grader integrity — agents must not rewrite the thing that grades them.
 * Compete-to-win vs Runcap / FeelGoot: protected evidence paths + config weaken +
 * optional base-pinned policy (.proofwork/policy.json from merge base when available).
 */
/**
 * Check-id namespaces an agent must not silently disable via `skipChecks`.
 *
 * Every namespace that can FAIL a run belongs here. Adding a check under a new
 * namespace without adding the namespace to this list creates a bypass: the agent
 * writes `skipChecks: ["<new.namespace>"]` into config and the gate stops enforcing
 * it with no complaint. Treat this list as part of the check's own definition.
 */
export const PROTECTED_CHECK_PREFIXES = [
    "integrity.",
    "ai_governance.",
    "agent_security.",
    // Added after a red-team finding: `regulatory.*` was omitted when those checks
    // shipped, so a repository could disable every transparency, record-keeping,
    // and automated-decision duty from config and still be certified.
    "regulatory.",
];
/**
 * Can this check be disabled from configuration?
 *
 * Matching runs in both directions on purpose. `skipChecks: ["integrity."]` is a
 * namespace-wide kill switch and `skipChecks: ["integrity.fake_green"]` is a
 * targeted one; a rule that only tested `startsWith(prefix)` would catch the
 * second and miss the first.
 */
export function isProtectedCheckId(id) {
    return PROTECTED_CHECK_PREFIXES.some((p) => id.startsWith(p) || p.startsWith(id));
}
export const DEFAULT_PROTECTED_GLOBS = [
    ".github/workflows/",
    "proofwork.config.json",
    ".proofwork/config.json",
    ".proofwork/policy.json",
    ".cursor/hooks.json",
    ".cursor/hooks/proofwork-",
    ".cursor/hooks/session-start.mjs",
    ".cursor/hooks/after-shell.mjs",
    ".cursor/hooks/stop-check.mjs",
    ".cursor/rules/proofwork.mdc",
    ".cursor/mcp.json",
    "AGENTS.md",
];
export function isProtectedPath(file, protectedPaths) {
    const f = file.replace(/\\/g, "/");
    for (const p of protectedPaths) {
        const pat = p.replace(/\\/g, "/");
        if (pat.endsWith("/")) {
            if (f.startsWith(pat) || f === pat.slice(0, -1))
                return true;
        }
        else if (f === pat || f.startsWith(`${pat}`)) {
            // prefix match for hooks like .cursor/hooks/proofwork-
            if (pat.endsWith("-") && f.startsWith(pat))
                return true;
            if (f === pat)
                return true;
            if (!pat.endsWith("-") && f.startsWith(`${pat}/`))
                return true;
        }
    }
    return false;
}
function loadPolicy(root) {
    const candidates = [".proofwork/policy.json", "proofwork.policy.json"];
    for (const rel of candidates) {
        const p = path.join(root, rel);
        if (!fs.existsSync(p))
            continue;
        try {
            const raw = JSON.parse(fs.readFileSync(p, "utf8"));
            const protected_paths = Array.isArray(raw.protected_paths)
                ? raw.protected_paths.map(String)
                : [...DEFAULT_PROTECTED_GLOBS];
            const allowed = Array.isArray(raw.allowed_path_prefixes)
                ? raw.allowed_path_prefixes.map(String)
                : undefined;
            return { version: 1, protected_paths, allowed_path_prefixes: allowed };
        }
        catch {
            // A malformed policy file falls back to the built-in protected paths
            // rather than to none. Failing open here would mean a single unparseable
            // character in this file silently unprotects the grader — which is
            // precisely the edit an agent would want to make.
        }
    }
    return { version: 1, protected_paths: [...DEFAULT_PROTECTED_GLOBS] };
}
/** Prefer policy content as it existed on the merge base (agent cannot edit the judge's rules). */
function loadBasePinnedPolicy(root, local) {
    // Resolve through the shared trusted resolver rather than reading the raw env:
    // PROOFWORK_BASE_REF is agent-settable, and pointing it at the agent's own branch
    // would make "base-pinned" policy read the policy the agent just edited.
    const { ref: base } = resolveBaseRef();
    if (!base)
        return local;
    const refs = [`origin/${base}:.proofwork/policy.json`, `${base}:.proofwork/policy.json`];
    for (const ref of refs) {
        const r = tryExec("git", ["show", ref], root, 5_000);
        if (!r.ok || !r.out.trim())
            continue;
        try {
            const raw = JSON.parse(r.out);
            const protected_paths = Array.isArray(raw.protected_paths)
                ? raw.protected_paths.map(String)
                : local.protected_paths;
            const allowed = Array.isArray(raw.allowed_path_prefixes)
                ? raw.allowed_path_prefixes.map(String)
                : local.allowed_path_prefixes;
            return { version: 1, protected_paths, allowed_path_prefixes: allowed };
        }
        catch {
            continue;
        }
    }
    return local;
}
function readJsonFile(root, rel) {
    const p = path.join(root, rel);
    if (!fs.existsSync(p))
        return null;
    try {
        return JSON.parse(fs.readFileSync(p, "utf8"));
    }
    catch {
        return null;
    }
}
function baseConfigRaw(root, rel) {
    const base = process.env.GITHUB_BASE_REF || process.env.PROOFWORK_BASE_REF;
    if (!base) {
        const show = tryExec("git", ["show", `HEAD:${rel}`], root, 5_000);
        return show.ok ? show.out : null;
    }
    for (const ref of [`origin/${base}:${rel}`, `${base}:${rel}`, `HEAD:${rel}`]) {
        const r = tryExec("git", ["show", ref], root, 5_000);
        if (r.ok && r.out.trim())
            return r.out;
    }
    return null;
}
/** Detect agent weakening the gate via config edits. */
export function detectConfigWeaken(root, changedFiles) {
    const hits = [];
    const configRels = ["proofwork.config.json", ".proofwork/config.json"].filter((r) => changedFiles.some((f) => f.replace(/\\/g, "/") === r));
    for (const rel of configRels) {
        const cur = readJsonFile(root, rel);
        if (!cur)
            continue;
        const prevRaw = baseConfigRaw(root, rel);
        let prev = null;
        if (prevRaw) {
            try {
                prev = JSON.parse(prevRaw);
            }
            catch {
                prev = null;
            }
        }
        const skip = Array.isArray(cur.skipChecks) ? cur.skipChecks.map(String) : [];
        // Match against every enforcing namespace, not just `integrity.` — a check in
        // any other namespace would otherwise be silently disable-able from config.
        const badSkip = skip.filter((s) => PROTECTED_CHECK_PREFIXES.some((prefix) => s.startsWith(prefix)));
        if (badSkip.length) {
            hits.push({
                id: "skip_protected_check",
                detail: `${rel} adds skipChecks for protected check(s): ${badSkip.join(", ")}`,
            });
        }
        if (cur.strictIntegrity === false && (prev == null || prev.strictIntegrity !== false)) {
            hits.push({ id: "disable_strict", detail: `${rel} sets strictIntegrity=false` });
        }
        const curMax = Number(cur.maxIdenticalFailures);
        const prevMax = prev != null ? Number(prev.maxIdenticalFailures) : NaN;
        if (Number.isFinite(curMax) && curMax > 2 && (!Number.isFinite(prevMax) || curMax > prevMax)) {
            hits.push({
                id: "raise_loop_limit",
                detail: `${rel} raises maxIdenticalFailures to ${curMax} (max-capacity ≤ 2)`,
            });
        }
        if (cur.failOnWarn === false && (prev == null || prev.failOnWarn !== false)) {
            hits.push({ id: "disable_failOnWarn", detail: `${rel} sets failOnWarn=false` });
        }
    }
    return hits;
}
function outOfScope(file, allowed) {
    if (!allowed?.length)
        return false;
    const f = file.replace(/\\/g, "/");
    if (f.startsWith(".proofwork/"))
        return false;
    return !allowed.some((a) => {
        const p = a.replace(/\\/g, "/");
        return f === p || f.startsWith(p.endsWith("/") ? p : `${p}/`) || f.startsWith(p);
    });
}
function isProofworkEngineRepo(root) {
    try {
        const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
        return pkg.name === "proofwork" && fs.existsSync(path.join(root, "action.yml"));
    }
    catch {
        return false;
    }
}
export function runGraderIntegrityChecks(root, git) {
    const localPolicy = loadPolicy(root);
    const policy = loadBasePinnedPolicy(root, localPolicy);
    const changed = (git?.changedFiles ?? []).map((f) => f.replace(/\\/g, "/"));
    const engine = isProofworkEngineRepo(root);
    // Report *how* the base was resolved, not just that one exists. A pin sourced
    // from an agent-settable env var is materially weaker than one the CI runner
    // set, and a reviewer reading the proof should be able to tell them apart.
    const baseResolution = resolveBaseRef();
    const basePinned = isTrustedBaseSource(baseResolution.source);
    const baseEvidence = {
        base_pinned: basePinned,
        base_ref: baseResolution.ref,
        base_ref_source: baseResolution.source,
    };
    if (!changed.length) {
        return [
            {
                id: "integrity.grader",
                title: "Grader integrity (immutable judge)",
                status: "pass",
                detail: "No changed files — grader surface untouched",
                evidence: { protected_paths: policy.protected_paths.length, ...baseEvidence },
            },
        ];
    }
    const existedOnHead = (file) => {
        const r = tryExec("git", ["cat-file", "-e", `HEAD:${file}`], root, 3_000);
        return r.ok;
    };
    // Only block *edits* to an existing judge — first-time scaffold adds (init) must pass.
    const protectedHits = changed.filter((f) => isProtectedPath(f, policy.protected_paths) && existedOnHead(f));
    const scopeHits = changed.filter((f) => outOfScope(f, policy.allowed_path_prefixes));
    const weaken = detectConfigWeaken(root, changed);
    // Config weaken always FAIL (even on the engine) — agents must not disable the gate.
    if (weaken.length || scopeHits.length) {
        const reasons = [
            ...weaken.map((w) => w.detail),
            ...scopeHits.map((f) => `Out-of-scope path: ${f}`),
        ];
        return [
            {
                id: "integrity.grader",
                title: "Grader integrity (immutable judge)",
                status: "fail",
                detail: `Agent must not rewrite the judge — ${reasons[0]}${reasons.length > 1 ? ` (+${reasons.length - 1} more)` : ""}`,
                evidence: {
                    protected_hits: protectedHits,
                    scope_hits: scopeHits,
                    config_weaken: weaken,
                    reasons,
                    ...baseEvidence,
                },
            },
        ];
    }
    if (protectedHits.length) {
        // Customer repos: FAIL (human approval). Engine repo: PASS note — we author the scaffolds.
        // Config weaken still FAILs above for everyone including the engine.
        if (engine) {
            return [
                {
                    id: "integrity.grader",
                    title: "Grader integrity (immutable judge)",
                    status: "pass",
                    detail: `Engine authoring scaffold paths (customer installs still block agents): ${protectedHits.slice(0, 4).join(", ")}`,
                    evidence: {
                        protected_hits: protectedHits,
                        engine_soft: true,
                        ...baseEvidence,
                    },
                },
            ];
        }
        return [
            {
                id: "integrity.grader",
                title: "Grader integrity (immutable judge)",
                status: "fail",
                detail: `Protected evidence path(s) edited — human approval required: ${protectedHits.slice(0, 6).join(", ")}`,
                evidence: {
                    protected_hits: protectedHits,
                    engine_soft: false,
                    ...baseEvidence,
                    policy_paths: policy.protected_paths,
                },
            },
        ];
    }
    return [
        {
            id: "integrity.grader",
            title: "Grader integrity (immutable judge)",
            status: "pass",
            detail: `Judge intact — no protected evidence edits (${changed.length} file(s) scanned)`,
            evidence: { changed: changed.length, ...baseEvidence },
        },
    ];
}
