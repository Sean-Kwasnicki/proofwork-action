import fs from "node:fs";
import path from "node:path";
import { buildGitContext } from "../gitContext.js";
import { isCi, tryExec } from "../util/exec.js";
export function inspectRepo(root, git) {
    const ctx = git ?? buildGitContext(root);
    return {
        root,
        is_git: ctx.isGit,
        branch: ctx.branch,
        commit: ctx.commit,
    };
}
export function runReadinessChecks(root, opts = {}) {
    const checks = [];
    const repo = inspectRepo(root, opts.git);
    const strictAuth = Boolean(opts.strictAuth);
    const fast = Boolean(opts.fast) || process.env.PROOFWORK_FAST === "1";
    /**
     * A bundle is not a git repository, and is not expected to be.
     *
     * Failing this in bundle mode would give the same agent two different verdicts
     * depending only on how it was delivered — a directory export failing where the
     * identical code in a clone passes. That is not a higher standard, it is an
     * incoherent one, and it would make intake unusable for exactly the in-use
     * agents this mode exists to serve.
     *
     * Skipping is not softening: the run still binds to one exact state, by content
     * digest instead of a commit, and every other check is unchanged. What is
     * genuinely lost is diff-derived evidence — the gate cannot see what changed, so
     * change-scoped checks fall back to the whole tree. That is stated here rather
     * than left for someone to infer from a green tick.
     */
    const bundleMode = Boolean(opts.bundle);
    checks.push({
        id: "git.repository",
        title: "Git repository present",
        status: repo.is_git ? "pass" : bundleMode ? "skip" : "fail",
        detail: repo.is_git
            ? `Git repo on branch ${repo.branch ?? "(unborn/no HEAD)"}`
            : bundleMode
                ? "Bundle intake — no git history. The proof is bound to a content digest " +
                    "instead of a commit, and change-scoped checks read the whole tree."
                : "Not a git repository — init git before trusting agent diffs",
        evidence: { branch: repo.branch, commit: repo.commit, bundle: bundleMode },
    });
    if (isCi() || fast) {
        checks.push({
            id: "github.auth",
            title: "GitHub CLI authenticated",
            status: "skip",
            detail: isCi()
                ? "Skipped in CI — Actions use GITHUB_TOKEN, not local gh auth"
                : "Skipped in --fast — local gh auth is not on the product critical path",
        });
    }
    else {
        const ghVer = tryExec("gh", ["--version"], root, 3_000);
        if (!ghVer.ok) {
            checks.push({
                id: "github.cli",
                title: "GitHub CLI available",
                status: "warn",
                detail: "gh not found on PATH — GitHub Action/PR workflows may be blocked",
            });
        }
        else {
            const ghAuth = tryExec("gh", ["auth", "status"], root, 4_000);
            const loggedIn = ghAuth.ok && /Logged in to/i.test(ghAuth.out);
            checks.push({
                id: "github.auth",
                title: "GitHub CLI authenticated",
                status: loggedIn ? "pass" : strictAuth ? "fail" : "warn",
                detail: loggedIn
                    ? "gh auth reports logged in"
                    : "gh is not authenticated — run: gh auth login (warn unless --strict-auth)",
                evidence: { snippet: ghAuth.out.slice(0, 240) },
            });
        }
    }
    // process.versions.node — zero subprocess latency
    const nodeVersion = process.versions.node ? `v${process.versions.node}` : "";
    checks.push({
        id: "runtime.node",
        title: "Node.js available",
        status: nodeVersion ? "pass" : "fail",
        detail: nodeVersion ? `Node ${nodeVersion}` : "Node.js not found — beachhead toolchain missing",
        evidence: { version: nodeVersion || null },
    });
    /**
     * Which ecosystem is this?
     *
     * Determined before anything is judged, because half the readiness checks are
     * about JavaScript tooling and a Python or Go repository has no business being
     * warned for lacking `package.json` and Vitest. Those warnings fired on every
     * non-Node project — the first thing a Python team saw was two complaints about
     * files their language does not use, which reads as a tool that does not know
     * what it is looking at.
     *
     * A skip says "this question does not apply here". That is the honest verdict
     * and it costs the project nothing, whereas a warning costs credibility on the
     * very first screen.
     */
    const pkgPath = path.join(root, "package.json");
    const hasPkg = fs.existsSync(pkgPath);
    const isPython = fs.existsSync(path.join(root, "pyproject.toml")) ||
        fs.existsSync(path.join(root, "requirements.txt")) ||
        fs.existsSync(path.join(root, "setup.py"));
    const isGo = fs.existsSync(path.join(root, "go.mod"));
    const isRust = fs.existsSync(path.join(root, "Cargo.toml"));
    const nonJs = !hasPkg && (isPython || isGo || isRust);
    const ecosystem = isPython ? "Python" : isGo ? "Go" : isRust ? "Rust" : "JavaScript/TypeScript";
    checks.push({
        id: "project.package_json",
        title: "package.json present",
        status: hasPkg ? "pass" : nonJs ? "skip" : "warn",
        detail: hasPkg
            ? "package.json found"
            : nonJs
                ? `${ecosystem} project — package.json does not apply`
                : "No package.json — outside default TS beachhead",
        evidence: { ecosystem },
    });
    const vitestConfigCandidates = [
        "vitest.config.ts",
        "vitest.config.js",
        "vitest.config.mjs",
        "vite.config.ts",
        "vite.config.js",
    ];
    const jestConfigCandidates = [
        "jest.config.ts",
        "jest.config.js",
        "jest.config.mjs",
        "jest.config.cjs",
    ];
    let hasVitestDep = false;
    let hasJestDep = false;
    if (fs.existsSync(pkgPath)) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
            hasVitestDep = Boolean(pkg.devDependencies?.vitest || pkg.dependencies?.vitest);
            hasJestDep = Boolean(pkg.devDependencies?.jest || pkg.dependencies?.jest);
        }
        catch {
            // An unparseable package.json leaves both flags false, and the config-file
            // checks below still run — so a project with a vitest.config.ts is still
            // recognised. The worst outcome is a warning that no test runner was found,
            // which is the safe direction: this cannot turn into a pass that was not
            // earned, only a complaint the author can see and explain.
            //
            // Rethrowing would be worse. A malformed manifest in one repository would
            // abort the whole run, and a gate that crashes on the repositories most in
            // need of grading is a gate nobody keeps installed.
        }
    }
    const hasVitestFile = vitestConfigCandidates.some((f) => fs.existsSync(path.join(root, f)));
    const hasJestFile = jestConfigCandidates.some((f) => fs.existsSync(path.join(root, f)));
    const beachheadOk = hasVitestDep || hasVitestFile || hasJestDep || hasJestFile;
    const runners = [
        hasVitestDep || hasVitestFile ? "vitest" : null,
        hasJestDep || hasJestFile ? "jest" : null,
    ].filter(Boolean);
    /**
     * Runners for other ecosystems, so the absence of Vitest is not mistaken for
     * the absence of testing.
     *
     * `integrity.verification` already decides whether a suite exists at all, in
     * any language. This check only asks whether a *runner this project could use*
     * is configured, and warning a Go module for not having Jest tells its authors
     * nothing except that the tool is not paying attention.
     */
    const pyRunner = fs.existsSync(path.join(root, "pytest.ini")) ||
        fs.existsSync(path.join(root, "tox.ini")) ||
        (() => {
            try {
                return /\[tool\.pytest|pytest/.test(fs.readFileSync(path.join(root, "pyproject.toml"), "utf8"));
            }
            catch {
                return false;
            }
        })();
    // `go test` ships with the toolchain: a Go module needs no runner configured,
    // so its presence is established by `go.mod` alone.
    const otherRunnerOk = (isPython && pyRunner) || isGo || isRust;
    checks.push({
        id: "project.vitest",
        title: "Test runner configured",
        status: beachheadOk || otherRunnerOk ? "pass" : nonJs ? "skip" : "warn",
        detail: beachheadOk
            ? `Test beachhead detected: ${runners.join(" + ")}`
            : otherRunnerOk
                ? `${ecosystem} project — ${isGo ? "go test is built in" : isRust ? "cargo test is built in" : "pytest configured"}`
                : nonJs
                    ? `${ecosystem} project — no JS runner expected; whether a suite exists is judged separately`
                    : "No Vitest/Jest beachhead yet — anti-fake-green still scans *.test.* / *.spec.* paths",
        evidence: { hasVitestDep, hasVitestFile, hasJestDep, hasJestFile, runners, ecosystem },
    });
    if (isCi() || fast) {
        checks.push({
            id: "tooling.agentsaver",
            title: "AgentSaver available (project memory)",
            status: "skip",
            detail: isCi()
                ? "Skipped in CI — AgentSaver is local session tooling, not a CI dependency"
                : "Skipped in --fast — session memory is optional locally",
        });
    }
    else {
        const agentsaver = tryExec("agentsaver", ["--help"], root, 3_000);
        checks.push({
            id: "tooling.agentsaver",
            title: "AgentSaver available (project memory)",
            status: agentsaver.ok ? "pass" : "warn",
            detail: agentsaver.ok
                ? "AgentSaver CLI found — use for session memory, do not reinvent"
                : "AgentSaver not on PATH — install/enable for continuity",
        });
    }
    const projectMcp = path.join(root, ".cursor", "mcp.json");
    const userMcp = path.join(process.env.USERPROFILE ?? process.env.HOME ?? "", ".cursor", "mcp.json");
    const hasProjectMcp = fs.existsSync(projectMcp);
    const hasUserMcp = Boolean(userMcp) && fs.existsSync(userMcp);
    if (isCi()) {
        checks.push({
            id: "cursor.mcp_config",
            title: "Cursor MCP config",
            status: "skip",
            detail: "Skipped in CI — Cursor MCP config is a local developer signal",
        });
    }
    else if (hasProjectMcp || hasUserMcp) {
        checks.push({
            id: "cursor.mcp_config",
            title: "Cursor MCP config",
            status: "pass",
            detail: hasProjectMcp
                ? `Project MCP config found (${projectMcp})`
                : `User MCP config found (${userMcp})`,
            evidence: { project: hasProjectMcp, user: hasUserMcp },
        });
    }
    else {
        checks.push({
            id: "cursor.mcp_config",
            title: "Cursor MCP config",
            status: fast ? "skip" : "warn",
            detail: "No project or user mcp.json — agents may lack proofwork_* tools",
            evidence: { project: false, user: false },
        });
    }
    return checks;
}
