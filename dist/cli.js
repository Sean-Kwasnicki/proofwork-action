#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { runAccept } from "./accept.js";
import { attestationPublicSummary, verifyAttestation } from "./attestation.js";
import { runCertify } from "./certify.js";
import { certificateId, writeCertificateDoc } from "./certificateDoc.js";
import { buildReportCard, renderReportCard } from "./reportCard.js";
import { scoreProof } from "./scoring.js";
import { writeConductArtifacts, verifyConductFile, CONDUCT_SCHEMA } from "./authority/conductRecord.js";
import { currentEntitlement, issuerPublicKey, storeLicense, verifyLicense } from "./license.js";
import { issueCredential, issueDeniedRecord, issuedCredentials, verifyCredentialFile } from "./credential.js";
import { allSignups, loadAccount, renderSignup, signOut, signUp } from "./account.js";
import { writeBadges } from "./badgeDoc.js";
import { depositCredential, openVault, renderVault, writeVaultPage } from "./vault.js";
import { renderFleet, reviewFleet } from "./fleet.js";
import { readEnforcementLog, renderEnforcement, summariseEnforcement } from "./guard/attestedGuard.js";
import { embedPublicKey, issuerPaths, issueLicenseFor, loadOrCreateIssuerKeys } from "./issuer.js";
import { closeBundle, describeBinding, openBundle } from "./bundle.js";
import { assessFreshness, freshnessLabel, scopeSentence } from "./staleness.js";
import { VERIFY_HOST_ENV, verifyHost } from "./verifyHost.js";
import { deliverCertificate } from "./payments/certificateMail.js";
import { buildDepositPayload, requestOidcToken, sendDeposit } from "./ci/deposit.js";
import { DEPOSIT_AUDIENCE } from "./server/deposit.js";
import { readRevocationList, renderRevocationList, republishRevocationList, revokeRecord, } from "./revocation.js";
import { renderStripeStatus, resolveStripe, stripeStatus } from "./payments/stripe.js";
import { renderTestCharge, runTestCharge } from "./payments/checkout.js";
import { appendLedgerEvent } from "./checks/spendLoop.js";
import { explainProof } from "./explain.js";
import { initProofwork } from "./init.js";
import { proofToAgentBrief, proofToMarkdown } from "./report.js";
import { runProof } from "./run.js";
import { runShare } from "./share.js";
function printHelp() {
    console.log(`Proofwork — Proof of Work for AI coding agents

Usage:
  proofwork check [--root <dir>] [--bundle <dir-or-zip>] [--out <file>] [--json] [--compact] [--quiet] [--fast] [--strict] [--strict-auth] [--readiness-only]

  --bundle grades a directory or archive that is not a git checkout — an agent
  already in production, exported rather than cloned. Same checks; the proof binds
  to a content digest instead of a commit and says so. See docs/INTAKE.md.

  proofwork status [--root <dir>] [--json]
  proofwork doctor [--root <dir>]
  proofwork init [--root <dir>] [--editor] [--home <proofwork-clone>]
  proofwork accept [--root <dir>] [--json]
  proofwork signup --email <you@co.com> [--name <n>] [--org <o>]
  proofwork whoami
  proofwork signout
  proofwork activate <license-key>
  proofwork license status [--json]
  proofwork license issue --subject <name> [--tier certified|assured] [--days <n>] [--repos a,b]
                          --days defaults to 31 (one billing period). A year needs --days 365.
  proofwork license keys [--embed]
  proofwork issuer records [--json]
  proofwork payments status [--json]
  proofwork payments test-charge [--amount <cents>] [--json]
  proofwork report [--root <dir>] [--json] [--subject <name>]
  proofwork certificate [--root <dir>] [--subject <name>] [--repo <id>] [--out <dir>]
  proofwork verify <record.json> [--json]
      Registry credential or authority conduct.json — no source required.
  proofwork publish <record.json>     needs PROOFWORK_VERIFY_URL
  proofwork vault [--html] [--json]
  proofwork fleet [--root <dir-of-repos>] [--json]
  proofwork enforcement [--json]
  proofwork certify [--root <dir>] [--json]
  proofwork share [--root <dir>]
  proofwork explain [--root <dir>]
  proofwork attest verify [--root <dir>]
  proofwork summary --in <proof.json>
  proofwork fingerprints reset [--root <dir>]
  proofwork ledger add --type failure --name <name> [--detail <text>] [--fingerprint <fp>]
  proofwork --help

Commands:
  check               Run readiness + integrity checks and emit a Proof JSON
  status              Fast agent brief (same as check --fast --quiet)
  doctor              Explain fails/warns with fix hints (install / CI debugging)
  explain             Plain-English PASS/FAIL meaning for humans
  init                Write the public Action (fail-on: never). --editor adds Cursor hooks
  accept              Customer acceptance gate — install incomplete until exit 0
  signup              Create a local profile (optional; the Action does not need one)
  whoami              Show the account and tier this machine is using
  signout             Remove the local account
  activate            Install a licence key on this machine (customer side)
  license status      Show the tier this machine is entitled to, and why
  license issue       Mint a licence — issuer only, needs the private key
  license keys        Show or embed the issuer public key — issuer only
  issuer records      Signups and issued records — issuer only
  payments status     Are we able to test payments, or not? Makes a real authenticated call
  payments test-charge  Put one test-mode payment on your dashboard. Refuses live keys.
  report              Graded report card — what each section scored and the route to 100
  certificate         Render the certificate document for a passing run
  verify              Verify a signed record handed to you — needs no call to Proofwork
  publish             Send a record to the verify host so its link resolves for others
  vault               Every credential you hold, re-verified on read
  fleet               Grade every agent under a directory — worst first
  enforcement         What the runtime spend guard actually allowed and refused
  certify             Issue CERTIFIED badge only at max-capacity (or DENY); appends attestation
  share               PR-ready Proofwork card (agents paste this — social object)
  attest verify       Verify tamper-evident attestation chain (local HMAC + hash links)
  summary             Print Markdown summary (for GitHub Step Summary)
  fingerprints reset  Clear deleted-code fingerprint store (local)
  ledger add          Append an event to .proofwork/ledger.json
  revoke <id>         Withdraw an issued record (issuer only) --reason "why"
  revoke --list       Show the current withdrawal list
  revoke --republish  Re-sign an unchanged list so its freshness rolls forward

Flags:
  --fast              Skip slow local probes (gh auth, agentsaver); integrity still runs
  --strict            Soft fake-green findings FAIL (max-capacity bar); also via config.strictIntegrity
  --home              Path to built Proofwork clone (written to .proofwork/install.json)
  --editor            init only: write Cursor hooks, MCP, and AGENTS.md
  --compact           Minified JSON (lowest agent parse latency); implied with PROOFWORK_COMPACT=1
  --quiet             One brief (+ blockers); for hooks/agents
`);
}
function parseArgs(argv) {
    const args = {
        command: "",
        root: process.cwd(),
        out: "",
        json: false,
        compact: process.env.PROOFWORK_COMPACT === "1",
        quiet: false,
        fast: process.env.PROOFWORK_FAST === "1",
        strict: process.env.PROOFWORK_STRICT === "1",
        strictAuth: false,
        readinessOnly: false,
        proofworkHome: process.env.PROOFWORK_HOME || "",
        editor: false,
        ledgerType: "note",
        ledgerName: "",
        ledgerDetail: "",
        ledgerFingerprint: "",
        summaryIn: "",
        subject: "",
        repoId: "",
        chargeAmount: 500,
        licenseKey: "",
        recordFile: "",
        email: "",
        org: "",
        tier: "certified",
        // One billing period, matching what a paid subscription actually buys.
        // This was 365, so every hand-issued key was a free year — the same defect
        // the fulfilment path had, sitting in the command an operator reaches for
        // when a customer needs a key in a hurry. A year is still available and now
        // has to be asked for: --days 365.
        days: 31,
        repos: [],
        embed: false,
        bundle: "",
        bundleMode: false,
        bundleLabel: "",
        reason: "",
        revokeList: false,
        republish: false,
    };
    if (argv.length === 0)
        return args;
    if (argv[0] === "ledger" && argv[1] === "add") {
        args.command = "ledger-add";
        for (let i = 2; i < argv.length; i += 1) {
            const a = argv[i];
            if (a === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
            else if (a === "--type")
                args.ledgerType = argv[++i] ?? "note";
            else if (a === "--name")
                args.ledgerName = argv[++i] ?? "";
            else if (a === "--detail")
                args.ledgerDetail = argv[++i] ?? "";
            else if (a === "--fingerprint")
                args.ledgerFingerprint = argv[++i] ?? "";
            else if (a === "--json")
                args.json = true;
        }
        return args;
    }
    if (argv[0] === "issuer" && argv[1] === "records") {
        args.command = "issuer-records";
        for (let i = 2; i < argv.length; i += 1)
            if (argv[i] === "--json")
                args.json = true;
        return args;
    }
    if (argv[0] === "enforcement") {
        args.command = "enforcement";
        for (let i = 1; i < argv.length; i += 1)
            if (argv[i] === "--json")
                args.json = true;
        return args;
    }
    if (argv[0] === "fleet") {
        args.command = "fleet";
        for (let i = 1; i < argv.length; i += 1) {
            const a = argv[i];
            if (a === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
            else if (a === "--json")
                args.json = true;
            else if (a === "--fast")
                args.fast = true;
        }
        return args;
    }
    if (argv[0] === "vault") {
        args.command = "vault";
        for (let i = 1; i < argv.length; i += 1) {
            if (argv[i] === "--json")
                args.json = true;
            else if (argv[i] === "--html")
                args.embed = true;
        }
        return args;
    }
    if (argv[0] === "signup" || argv[0] === "whoami" || argv[0] === "signout") {
        args.command = argv[0];
        for (let i = 1; i < argv.length; i += 1) {
            const a = argv[i];
            if (a === "--email")
                args.email = argv[++i] ?? "";
            else if (a === "--name")
                args.subject = argv[++i] ?? "";
            else if (a === "--org")
                args.org = argv[++i] ?? "";
            else if (a === "--json")
                args.json = true;
        }
        return args;
    }
    if (argv[0] === "verify") {
        args.command = "verify";
        args.recordFile = argv[1] ?? "";
        // `--root` and `--bundle` say which code to check the record against. This
        // branch returned before parsing them, so the freshness comparison silently
        // used the current directory — and reported STALE against whatever repo the
        // reader happened to be standing in.
        for (let i = 2; i < argv.length; i += 1) {
            const a = argv[i];
            if (a === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
            else if (a === "--bundle")
                args.bundle = argv[++i] ?? "";
            else if (a === "--json")
                args.json = true;
        }
        return args;
    }
    if (argv[0] === "activate") {
        args.command = "activate";
        args.licenseKey = argv[1] ?? "";
        return args;
    }
    if (argv[0] === "ci-deposit") {
        args.command = "ci-deposit";
        for (let i = 1; i < argv.length; i += 1) {
            if (argv[i] === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
            else if (argv[i] === "--subject")
                args.subject = argv[++i] ?? "";
        }
        return args;
    }
    if (argv[0] === "publish") {
        args.command = "publish";
        args.recordFile = argv[1] ?? "";
        return args;
    }
    if (argv[0] === "revoke") {
        args.command = "revoke";
        // `--list` and `--republish` take no record id; anything else is one.
        args.recordFile = argv[1] && !argv[1].startsWith("--") ? argv[1] : "";
        const r = argv.indexOf("--reason");
        if (r !== -1)
            args.reason = argv[r + 1] ?? "";
        if (argv.includes("--list"))
            args.revokeList = true;
        if (argv.includes("--republish"))
            args.republish = true;
        if (argv.includes("--json"))
            args.json = true;
        return args;
    }
    if (argv[0] === "license" || argv[0] === "licence") {
        const sub = argv[1] ?? "status";
        args.command = `license-${sub}`;
        for (let i = 2; i < argv.length; i += 1) {
            const a = argv[i];
            if (a === "--json")
                args.json = true;
            else if (a === "--embed")
                args.embed = true;
            else if (a === "--subject")
                args.subject = argv[++i] ?? "";
            else if (a === "--tier")
                args.tier = argv[++i] ?? "certified";
            else if (a === "--days")
                args.days = Number(argv[++i] ?? "31");
            else if (a === "--repos")
                args.repos = (argv[++i] ?? "").split(",").filter(Boolean);
        }
        return args;
    }
    if (argv[0] === "payments" && (argv[1] === "status" || argv[1] === "test-charge")) {
        args.command = argv[1] === "status" ? "payments-status" : "payments-test-charge";
        for (let i = 2; i < argv.length; i += 1) {
            if (argv[i] === "--json")
                args.json = true;
            else if (argv[i] === "--amount")
                args.chargeAmount = Number(argv[++i] ?? "500");
        }
        return args;
    }
    if (argv[0] === "fingerprints" && argv[1] === "reset") {
        args.command = "fingerprints-reset";
        for (let i = 2; i < argv.length; i += 1) {
            if (argv[i] === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
        }
        return args;
    }
    if (argv[0] === "attest" && argv[1] === "verify") {
        args.command = "attest-verify";
        for (let i = 2; i < argv.length; i += 1) {
            if (argv[i] === "--root")
                args.root = path.resolve(argv[++i] ?? process.cwd());
            else if (argv[i] === "--json")
                args.json = true;
        }
        return args;
    }
    args.command = argv[0] ?? "";
    for (let i = 1; i < argv.length; i += 1) {
        const a = argv[i];
        if (a === "--root")
            args.root = path.resolve(argv[++i] ?? process.cwd());
        else if (a === "--bundle")
            args.bundle = argv[++i] ?? "";
        else if (a === "--out")
            args.out = path.resolve(argv[++i] ?? "");
        else if (a === "--in")
            args.summaryIn = path.resolve(argv[++i] ?? "");
        else if (a === "--json")
            args.json = true;
        else if (a === "--compact")
            args.compact = true;
        else if (a === "--quiet")
            args.quiet = true;
        else if (a === "--fast")
            args.fast = true;
        else if (a === "--strict")
            args.strict = true;
        else if (a === "--strict-auth")
            args.strictAuth = true;
        else if (a === "--readiness-only")
            args.readinessOnly = true;
        else if (a === "--home")
            args.proofworkHome = path.resolve(argv[++i] ?? "");
        else if (a === "--editor")
            args.editor = true;
        else if (a === "--subject")
            args.subject = argv[++i] ?? "";
        else if (a === "--repo")
            args.repoId = argv[++i] ?? "";
        else if (a === "--help" || a === "-h")
            args.command = "help";
    }
    return args;
}
function ghEscape(s) {
    return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
/** GitHub Actions workflow commands — file:line when evidence has it. */
function emitCiAnnotations(proof) {
    if (!process.env.GITHUB_ACTIONS)
        return;
    let filed = 0;
    for (const c of proof.checks) {
        if (c.status !== "fail" && c.status !== "warn")
            continue;
        const hard = c.evidence?.hard;
        const soft = c.evidence?.soft;
        const hits = c.evidence?.hits;
        const rows = [];
        if (Array.isArray(hard)) {
            for (const h of hard) {
                rows.push({
                    file: h.file,
                    line: h.line,
                    msg: `${h.id ?? c.id}: ${h.why ?? c.detail}`,
                });
            }
        }
        if (Array.isArray(soft) && c.status === "warn") {
            for (const h of soft) {
                rows.push({
                    file: h.file,
                    line: h.line,
                    msg: `${h.id ?? c.id}: ${h.why ?? c.detail}`,
                });
            }
        }
        if (Array.isArray(hits)) {
            for (const h of hits) {
                rows.push({
                    file: h.file,
                    msg: `reintroduction: ${h.sample ?? c.detail}`,
                });
            }
        }
        for (const r of rows.slice(0, 30)) {
            const level = c.status === "fail" ? "error" : "warning";
            const loc = r.file && r.line
                ? ` file=${r.file},line=${r.line}`
                : r.file
                    ? ` file=${r.file}`
                    : "";
            process.stdout.write(`::${level}${loc} title=Proofwork::${ghEscape(r.msg)}\n`);
            filed += 1;
        }
    }
    if (filed === 0) {
        for (const b of proof.blockers) {
            process.stdout.write(`::error title=Proofwork::${ghEscape(b)}\n`);
        }
    }
    if (proof.ok && proof.timing) {
        process.stdout.write(`::notice title=Proofwork::PASS in ${proof.timing.total_ms}ms\n`);
    }
}
const DOCTOR_HINTS = {
    "git.repository": "Run inside a git repo: git init && git add -A && git commit -m init",
    "github.auth": "Optional locally: gh auth login (skip with --fast / in CI)",
    "github.cli": "Install GitHub CLI if you want local gh checks",
    "runtime.node": "Install Node.js >= 20",
    "project.package_json": "Add package.json for the TS/JS beachhead",
    "project.vitest": "Add vitest or jest (devDependency or config file) for clearer beachhead signal",
    "tooling.agentsaver": "Optional: install AgentSaver for session memory",
    "cursor.mcp_config": "Add .cursor/mcp.json pointing at proofwork-mcp (see docs/MCP.md)",
    "integrity.fake_green": "Remove it.skip / .only / empty tests from changed test files (or proofwork-ignore)",
    "integrity.reintroduction": "Don't re-add deleted logic; or proofwork fingerprints reset if store is polluted",
    "integrity.spend_loop": "Stop repeating the same failing command; clear .proofwork/ledger.json after fixing",
    "integrity.grader": "Do not edit workflows/hooks/proofwork config to pass — ask a human; revert grader changes",
};
function runDoctor(root) {
    const proof = runProof({ root, fast: true });
    writeProofFiles(root, "", proof, true);
    console.log(proofToAgentBrief(proof));
    console.log("");
    console.log("Doctor hints:");
    let n = 0;
    for (const c of proof.checks) {
        if (c.status !== "fail" && c.status !== "warn")
            continue;
        const hint = DOCTOR_HINTS[c.id] ?? "See docs/INSTALL.md and the check detail above.";
        console.log(`- [${c.status.toUpperCase()}] ${c.id}`);
        console.log(`  ${c.detail}`);
        console.log(`  → ${hint}`);
        n += 1;
    }
    if (n === 0) {
        console.log("- All clear. Add Sean-Kwasnicki/proofwork-action@v1 with fail-on: never (docs/INSTALL.md).");
    }
    else if (proof.checks.some((c) => c.status === "fail")) {
        // The route out, for someone who does not write the code themselves.
        // "See INSTALL.md" is the right pointer for a configuration problem and no
        // help at all when the answer is "your agent has to fix these findings".
        console.log("");
        console.log("Fixing these:");
        console.log("  proofwork report        the graded card, with every finding and how to clear it");
        console.log("  Paste that whole report into your coding agent — it lists each one.");
    }
    process.exit(proof.ok ? 0 : 2);
}
/**
 * Write the proof and its companions.
 *
 * ## Read-only means read-only
 *
 * `PROOFWORK_READONLY=1` exists so that grading leaves the graded repository
 * exactly as it was found. This function ignored it: `--out` redirected only the
 * numbered proof, while `latest.json`, `latest.md`, `latest-brief.txt`, and
 * `latest-story.txt` were always written into `<root>/.proofwork`.
 *
 * The consequences were real in both directions. The GitHub Action sets that flag
 * and then relies on a clean tree, so every customer running the gate in CI had
 * their checkout dirtied by the act of being checked. And grading somebody else's
 * corpus wrote five files into each of their repositories — which is how this was
 * found: a corpus that had been explicitly declared off-limits acquired artifacts
 * from being measured.
 *
 * A tool that modifies what it inspects cannot claim its measurement describes
 * what was there before it ran.
 *
 * Under read-only with no `--out`, nothing is written and the caller is told so
 * by an empty return. With `--out`, everything goes to that directory, including
 * the companions — a destination the caller named is a destination they chose.
 */
function writeProofFiles(root, out, proof, compact) {
    const readOnly = process.env.PROOFWORK_READONLY === "1";
    if (readOnly && !out)
        return "";
    const outPath = out || path.join(root, ".proofwork", `proof-${proof.created_at.replace(/[:.]/g, "-")}.json`);
    const dir = path.dirname(outPath);
    fs.mkdirSync(dir, { recursive: true });
    const body = compact ? `${JSON.stringify(proof)}\n` : `${JSON.stringify(proof, null, 2)}\n`;
    fs.writeFileSync(outPath, body, "utf8");
    // Companions sit beside the proof rather than in the subject tree, so `--out`
    // moves the whole artifact set and not merely one file of it.
    fs.writeFileSync(path.join(dir, "latest.json"), body, "utf8");
    fs.writeFileSync(path.join(dir, "latest.md"), proofToMarkdown(proof), "utf8");
    fs.writeFileSync(path.join(dir, "latest-brief.txt"), `${proofToAgentBrief(proof)}\n`, "utf8");
    if (proof.story) {
        fs.writeFileSync(path.join(dir, "latest-story.txt"), `${proof.story}\n`, "utf8");
    }
    writeConductArtifacts(dir, proof, { subject: path.basename(root) });
    return outPath;
}
function runCheck(args) {
    const proof = runProof({
        root: args.root,
        strictAuth: args.strictAuth,
        readinessOnly: args.readinessOnly,
        fast: args.fast,
        strict: args.strict || undefined,
        bundle: args.bundleMode,
    });
    const outPath = writeProofFiles(args.root, args.out, proof, args.compact || args.quiet);
    if (process.env.GITHUB_STEP_SUMMARY && !args.quiet) {
        try {
            fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, proofToMarkdown(proof), "utf8");
        }
        catch {
            // ignore summary write failures
        }
    }
    emitCiAnnotations(proof);
    if (args.json) {
        process.stdout.write(args.compact || args.quiet
            ? `${JSON.stringify(proof)}\n`
            : `${JSON.stringify(proof, null, 2)}\n`);
        process.exit(proof.ok ? 0 : 2);
    }
    if (args.quiet) {
        process.stdout.write(`${proofToAgentBrief(proof)}\n`);
        process.exit(proof.ok ? 0 : 2);
    }
    console.log(`Proofwork ${proof.ok ? "PASS" : "FAIL"}`);
    // Empty when running read-only without --out: nothing was written, and saying
    // "Wrote " with no path reads as a bug.
    if (outPath)
        console.log(`Wrote ${outPath}`);
    else
        console.log("Read-only run — no artifacts written into the graded repository.");
    if (proof.timing) {
        console.log(`timing: total=${proof.timing.total_ms}ms git=${proof.timing.git_ms}ms checks=${proof.timing.checks_ms}ms`);
    }
    console.log(`summary: pass=${proof.summary.passed} fail=${proof.summary.failed} warn=${proof.summary.warned} skip=${proof.summary.skipped}`);
    for (const c of proof.checks) {
        const mark = c.status === "pass"
            ? "PASS"
            : c.status === "fail"
                ? "FAIL"
                : c.status === "warn"
                    ? "WARN"
                    : "SKIP";
        console.log(`- [${mark}] ${c.id}: ${c.detail}`);
    }
    if (proof.blockers.length) {
        console.log("blockers:");
        for (const b of proof.blockers)
            console.log(`  - ${b}`);
    }
    process.exit(proof.ok ? 0 : 2);
}
async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (!args.command || args.command === "help" || args.command === "--help") {
        printHelp();
        process.exit(args.command ? 0 : 1);
    }
    /**
     * `--bundle` points the run at a directory or an expanded archive.
     *
     * Resolved once, here, rather than inside each command: the alternative is
     * every command growing its own copy of "is this a zip?", and the commands that
     * forgot would silently grade the archive file itself as an empty repository.
     *
     * Cleanup is registered on exit rather than written at the end of each command
     * path, because several of them call `process.exit` directly and a trailing
     * cleanup line would never run.
     */
    if (args.bundle) {
        try {
            const src = openBundle(args.bundle);
            args.root = src.root;
            args.bundleMode = true;
            args.bundleLabel = src.label;
            if (src.tempDir)
                process.on("exit", () => closeBundle(src));
        }
        catch (e) {
            process.stderr.write(`\n  ${e instanceof Error ? e.message : String(e)}\n\n`);
            process.exit(1);
        }
    }
    if (args.command === "status") {
        // Alias: agent hot path
        args.command = "check";
        args.fast = true;
        args.quiet = true;
        args.compact = true;
        runCheck(args);
        return;
    }
    if (args.command === "doctor") {
        runDoctor(args.root);
        return;
    }
    if (args.command === "init") {
        const result = initProofwork(args.root, {
            proofworkHome: args.proofworkHome || undefined,
            editor: args.editor,
        });
        console.log("Proofwork init complete");
        for (const c of result.created)
            console.log(`  [created] ${c}`);
        for (const s of result.skipped)
            console.log(`  [skipped] ${s}`);
        if (args.editor) {
            console.log("Next: proofwork accept --root <dir>  (must exit 0)");
        }
        else {
            console.log("Next: open a pull request. fail-on is never until you change it.");
            console.log("      Pin the Action by SHA before enforcing. --editor adds Cursor hooks.");
        }
        process.exit(0);
    }
    if (args.command === "accept") {
        const report = runAccept(args.root);
        if (args.json) {
            process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
        }
        else {
            console.log(report.ok ? "Proofwork ACCEPT PASS" : "Proofwork ACCEPT FAIL");
            console.log(`Wrote ${path.join(args.root, ".proofwork", "ACCEPTANCE.json")}`);
            for (const i of report.items) {
                console.log(`- [${i.ok ? "PASS" : "FAIL"}] ${i.id}: ${i.detail}`);
            }
            if (!report.ok) {
                console.log("Delivery incomplete until every item PASSes. See docs/DELIVERY.md");
            }
        }
        process.exit(report.ok ? 0 : 2);
    }
    if (args.command === "issuer-records") {
        // Issuer-side only. Answers "who signed up and what have we issued?" — the
        // two questions a business asks about itself, kept apart from the registry,
        // which answers a question about a customer.
        const signups = allSignups();
        const records = issuedCredentials();
        if (args.json) {
            process.stdout.write(`${JSON.stringify({ signups, records }, null, 2)}\n`);
            process.exit(0);
        }
        const rule = "─".repeat(74);
        process.stdout.write(`\n  ISSUER RECORDS\n  ${rule}\n\n` +
            `  Signups: ${signups.length}\n` +
            signups
                .slice(-15)
                .map((s) => `    ${s.created_at.slice(0, 10)}  ${s.email.padEnd(34)} ${s.organisation ?? ""}`)
                .join("\n") +
            `\n\n  Records issued: ${records.length}` +
            ` (${records.filter((r) => r.verdict === "pass").length} certified,` +
            ` ${records.filter((r) => r.verdict === "fail").length} denied)\n` +
            records
                .slice(-15)
                .map((r) => `    ${r.issued_at.slice(0, 10)}  ${r.record_id}  ` +
                `${r.verdict === "pass" ? "CERTIFIED" : "DENIED   "}  ${r.subject}`)
                .join("\n") +
            `\n\n  Signups are unverified addresses — nothing confirms the person owns\n` +
            `  them. Treat the list as intent, not as consent to contact.\n\n`);
        process.exit(0);
    }
    if (args.command === "enforcement") {
        const summary = summariseEnforcement(readEnforcementLog());
        process.stdout.write(args.json ? `${JSON.stringify(summary, null, 2)}\n` : renderEnforcement(summary));
        // Non-zero on a broken chain: a tampered enforcement log is a finding.
        process.exit(summary.chainIntact ? 0 : 1);
    }
    if (args.command === "fleet") {
        const report = reviewFleet(args.root, { fast: true });
        process.stdout.write(args.json ? `${JSON.stringify(report, null, 2)}\n` : renderFleet(report));
        // Non-zero when any agent is denied, so a scheduled fleet review can gate.
        process.exit(report.denied > 0 || report.errored > 0 ? 1 : 0);
    }
    if (args.command === "vault") {
        const v = openVault();
        if (args.json) {
            process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
        }
        else {
            process.stdout.write(renderVault(v));
            if (args.embed) {
                const file = writeVaultPage(v);
                process.stdout.write(`  Shareable page: ${file}\n\n`);
            }
        }
        process.exit(v.invalid > 0 ? 1 : 0);
    }
    if (args.command === "signup") {
        if (!args.email) {
            process.stderr.write("Usage: proofwork signup --email <you@company.com> [--name <n>] [--org <o>]\n");
            process.exit(1);
        }
        try {
            const result = signUp({
                email: args.email,
                ...(args.subject ? { name: args.subject } : {}),
                ...(args.org ? { organisation: args.org } : {}),
            });
            process.stdout.write(args.json ? `${JSON.stringify(result, null, 2)}\n` : renderSignup(result));
            process.exit(0);
        }
        catch (e) {
            process.stderr.write(`\n  ${e instanceof Error ? e.message : String(e)}\n\n`);
            process.exit(1);
        }
    }
    if (args.command === "whoami") {
        const account = loadAccount();
        const entitlement = currentEntitlement();
        if (args.json) {
            process.stdout.write(`${JSON.stringify({ account, entitlement }, null, 2)}\n`);
            process.exit(account ? 0 : 1);
        }
        if (!account) {
            process.stdout.write("\n  Not signed in.\n\n  proofwork signup --email <you@company.com>\n\n" +
                "  Signing up is required even for the free tier.\n\n");
            process.exit(1);
        }
        /**
         * A licence installed for a different organisation is called out, not just
         * quietly ignored.
         *
         * Showing a lower tier with no explanation is the same confusion in the other
         * direction: someone who has paid sees "free" and has no idea why. The
         * mismatch names both organisations and what to do about it.
         */
        const otherOrg = !entitlement.valid && entitlement.payload && account.organisation
            ? entitlement.payload.subject
            : null;
        process.stdout.write(`\n  ${account.email}\n\n` +
            `    Account  ${account.account_id}\n` +
            (account.organisation ? `    Org      ${account.organisation}\n` : "") +
            `    Tier     ${entitlement.tier}\n` +
            (entitlement.valid && entitlement.payload
                ? `    Licence  ${entitlement.payload.subject}, expires ${entitlement.payload.expires_at.slice(0, 10)}\n`
                : "") +
            "\n" +
            (otherOrg
                ? `  This machine holds a licence issued to "${otherOrg}", which is not the\n` +
                    `  organisation you are signed in as. Running the free gate rather than\n` +
                    `  lending one organisation's entitlement to another.\n\n` +
                    `    proofwork activate <key>     install the licence for ${account.organisation}\n` +
                    `    proofwork signup --org "${otherOrg}"\n` +
                    `                                 or sign in as the organisation it names\n\n`
                : ""));
        process.exit(0);
    }
    if (args.command === "signout") {
        process.stdout.write(signOut() ? "\n  Signed out.\n\n" : "\n  Was not signed in.\n\n");
        process.exit(0);
    }
    if (args.command === "activate") {
        if (!args.licenseKey) {
            process.stderr.write("Usage: proofwork activate <license-key>\n");
            process.exit(1);
        }
        const verdict = verifyLicense(args.licenseKey);
        if (!verdict.valid) {
            // The reason is printed rather than a generic rejection. A customer who
            // pasted a truncated key, or whose licence lapsed yesterday, needs to know
            // which of those happened — "invalid licence" sends them to support for
            // something they could have fixed in ten seconds.
            process.stderr.write(`\n  Licence not accepted.\n\n  ${verdict.reason}\n\n`);
            process.exit(1);
        }
        const stored = storeLicense(args.licenseKey);
        const p = verdict.payload;
        process.stdout.write(`\n  Licence accepted.\n\n` +
            `    Tier      ${p.tier}\n` +
            `    Issued to ${p.subject}\n` +
            `    Expires   ${p.expires_at.slice(0, 10)}\n` +
            `    Repos     ${p.repos.join(", ")}\n` +
            `    Stored    ${stored}\n\n` +
            `  Stored outside any repository, so it cannot be committed by accident.\n\n` +
            `  Run \`proofwork report\` for the full graded breakdown.\n\n`);
        process.exit(0);
    }
    if (args.command === "license-status") {
        const verdict = currentEntitlement();
        if (args.json) {
            process.stdout.write(`${JSON.stringify(verdict, null, 2)}\n`);
            process.exit(verdict.valid ? 0 : 1);
        }
        process.stdout.write(`\n  Entitlement: ${verdict.tier.toUpperCase()}\n\n  ${verdict.reason ?? "Licence valid."}\n` +
            (verdict.payload
                ? `\n    Issued to ${verdict.payload.subject}\n    Expires   ${verdict.payload.expires_at.slice(0, 10)}\n`
                : "") +
            "\n");
        process.exit(verdict.valid ? 0 : 1);
    }
    if (args.command === "license-keys") {
        const keys = loadOrCreateIssuerKeys();
        const paths = issuerPaths();
        process.stdout.write(`\n  Issuer key ${keys.created ? "created" : "loaded"}.\n\n` +
            `    key id      ${keys.keyId}\n` +
            `    private     ${paths.privateKey}\n` +
            `    public      ${paths.publicKey}\n\n` +
            `  The private key never leaves this machine and is not in the repository.\n` +
            `  Back it up: losing it invalidates every licence and registry record.\n\n`);
        if (args.embed) {
            const res = embedPublicKey(process.cwd(), keys.publicKeyPem);
            process.stdout.write(res.changed
                ? `  Embedded the public key into ${res.file}. Rebuild to ship it.\n\n`
                : `  ${res.file} already carries this key — nothing to change.\n\n`);
        }
        else {
            process.stdout.write(`  Run with --embed to write the public half into the client build.\n\n`);
        }
        process.exit(0);
    }
    if (args.command === "license-issue") {
        if (!args.subject) {
            process.stderr.write("Usage: proofwork license issue --subject <name> [--tier certified|assured]\n");
            process.exit(1);
        }
        if (args.tier !== "certified" && args.tier !== "assured") {
            process.stderr.write(`Unknown tier "${args.tier}". Use certified or assured.\n`);
            process.exit(1);
        }
        const issued = issueLicenseFor({
            subject: args.subject,
            tier: args.tier,
            days: args.days,
            repos: args.repos,
        });
        if (args.json) {
            process.stdout.write(`${JSON.stringify(issued, null, 2)}\n`);
            process.exit(0);
        }
        process.stdout.write(`\n  Licence issued to ${issued.payload.subject}.\n\n` +
            `    tier     ${issued.payload.tier}\n` +
            `    expires  ${issued.payload.expires_at.slice(0, 10)}\n` +
            `    repos    ${issued.payload.repos.join(", ")}\n` +
            `    key id   ${issued.keyId}\n\n` +
            `  Send them this key:\n\n${issued.token}\n\n` +
            `  They run:  proofwork activate <key>\n\n`);
        process.exit(0);
    }
    if (args.command === "payments-status") {
        const status = await stripeStatus();
        if (args.json) {
            process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
        }
        else {
            process.stdout.write(renderStripeStatus(status));
        }
        process.exit(status.reachable ? 0 : 1);
    }
    if (args.command === "payments-test-charge") {
        const config = resolveStripe();
        const result = await runTestCharge({ amountCents: args.chargeAmount, config });
        if (args.json) {
            process.stdout.write(`${JSON.stringify({ mode: config.mode, ...result }, null, 2)}\n`);
        }
        else {
            process.stdout.write(renderTestCharge(result, config.mode));
        }
        process.exit(result.ok ? 0 : 1);
    }
    if (args.command === "report") {
        const proof = runProof({
            root: args.root, fast: args.fast, strict: args.strict, bundle: args.bundleMode,
        });
        const entitlement = currentEntitlement();
        const subject = args.subject || path.basename(args.root);
        const card = buildReportCard(proof, subject);
        /**
         * Conduct artefacts go where the caller asked, or to the operator cwd.
         * They never go into the graded tree, and under `PROOFWORK_READONLY`
         * they are not written at all unless `--out` named a destination.
         * The Action's working directory *is* the graded repository; writing
         * `.proofwork/` there is the bug this product already shipped twice.
         */
        const readOnly = process.env.PROOFWORK_READONLY === "1";
        const reportDir = args.out ? args.out : readOnly ? "" : path.join(process.cwd(), ".proofwork");
        if (reportDir)
            writeConductArtifacts(reportDir, proof, { subject });
        if (args.json) {
            process.stdout.write(`${JSON.stringify(card, null, 2)}\n`);
        }
        else {
            process.stdout.write(renderReportCard(card));
            if (entitlement.tier === "free") {
                process.stdout.write("\n  This run is not written to the registry. Activate a licence to issue a signed record.\n");
            }
        }
        // A report card is information, not a gate. It exits non-zero on a failing
        // run so CI still blocks, but the card prints either way — a customer who
        // failed is exactly the one who needs to read it. Free and paid print the
        // same card. The licence buys the citable record, not the line number.
        process.exit(proof.ok ? 0 : 2);
    }
    if (args.command === "certificate") {
        const proof = runProof({
            root: args.root, fast: args.fast, strict: true, bundle: args.bundleMode,
        });
        const score = scoreProof(proof);
        /**
         * Artifacts go to the operator's working directory, not the graded repo.
         *
         * The previous default wrote certificates, badges, and records into
         * `<subject>/.proofwork/`. That is wrong for a tool routinely pointed at code
         * somebody else owns: it dirties their working tree, appears in their
         * `git status`, and can be swept into a commit by whoever next runs
         * `git add -A`. A reviewer grading thirteen repositories modified all
         * thirteen just by looking at them.
         *
         * Grading is a read. Where the *output* lands is the operator's choice, so it
         * defaults to where they are standing and moves with `--out`.
         */
        const artifactDir = args.out || path.join(process.cwd(), ".proofwork");
        const conduct = writeConductArtifacts(artifactDir, proof, {
            subject: args.subject || path.basename(args.root),
        });
        if (!proof.ok) {
            console.error("Not certified — no certificate issued.");
            console.error("");
            console.error(`  ${score.final}/100 (${score.band.toUpperCase()})`);
            console.error(`  ${proof.blockers.length} blocking finding(s).`);
            /**
             * A failing run still produces a signed record.
             *
             * Previously it produced nothing, which meant the only durable artefacts
             * this product ever created were trophies. A buyer shown three certificates
             * could not tell whether there had been three runs or thirty. Signing the
             * denial does not stop anyone hiding it — but it changes hiding from "the
             * failure was never written down" into "a numbered record is missing",
             * which is a question a reader can actually ask.
             */
            try {
                const entitlement = currentEntitlement();
                const tier = entitlement.tier === "assured" ? "assured" : "certified";
                const failedCard = buildReportCard(proof, args.subject || path.basename(args.root));
                const reasons = failedCard.categories
                    .filter((c) => c.status === "failed")
                    .flatMap((c) => c.lost_because);
                const denied = issueDeniedRecord({
                    proof,
                    subject: args.subject || path.basename(args.root),
                    tier,
                    assertions: score.assertions,
                    score: score.final,
                    reasons,
                    outDir: artifactDir,
                });
                depositCredential(denied.entry);
                console.error("");
                console.error(`  A signed DENIED record was issued: ${denied.entry.record_id}`);
                console.error(`  ${denied.recordPath}`);
                console.error(`  It verifies like a certificate and cannot be edited into a pass.`);
                console.error(`  Conduct record (authority edition, includes DENIED): ${conduct.jsonPath}`);
            }
            catch (e) {
                // No private key means this is a customer machine, which is normal.
                console.error("");
                console.error(`  No denial record issued: ${e instanceof Error ? e.message : String(e)}`);
            }
            console.error("");
            console.error("  Run `proofwork report` to see which sections lost points and how to");
            console.error("  recover them. There is no certificate for a failing run.");
            process.exit(2);
        }
        const subject = args.subject || path.basename(args.root);
        // `artifactDir` was computed above and then not passed, so every write fell
        // back to `<subject>/.proofwork` — the exact behaviour the default was
        // changed to prevent. Computing the right destination and not using it is
        // worse than not computing it: the code reads as fixed.
        const file = writeCertificateDoc(args.root, {
            proof,
            subject,
            ...(args.repoId ? { repository: args.repoId } : {}),
            assertions: score.assertions,
        }, artifactDir);
        console.log(`Certificate written to ${file}`);
        console.log(`  conduct ${conduct.jsonPath}`);
        console.log(`  id      ${certificateId(proof)}`);
        console.log(`  grade   ${buildReportCard(proof).overall.grade} · ${score.final}/100`);
        // Named by what it actually is. Printing "commit unbound" for a bundle-bound
        // proof said the wrong thing on the surface a customer reads first.
        const bound = describeBinding(proof.binding ?? { commit: proof.repo.commit });
        console.log(`  ${bound.label.padEnd(7)} ${bound.short}`);
        // Sign the run into the registry. Without this the customer holds a document
        // they could have written themselves; the signature is what a third party
        // can check, and it is the only part of this they are actually buying.
        //
        // Only on the issuer's machine — a customer running this has no private key
        // and gets the document alone, which is the correct split.
        try {
            const entitlement = currentEntitlement();
            const tier = entitlement.tier === "assured" ? "assured" : "certified";
            const issued = issueCredential({
                proof,
                subject,
                tier,
                assertions: score.assertions,
                score: score.final,
                outDir: artifactDir,
            });
            console.log("");
            console.log(`  record  ${issued.entry.record_id}   ${issued.recordPath}`);
            console.log(`  Hand that file to anyone. They verify it with:`);
            console.log(`    proofwork verify ${path.basename(issued.recordPath)}`);
            /**
             * Email the certificate.
             *
             * Awaited rather than fired off, because this branch ends in
             * `process.exit(0)` and a pending send would simply be killed — the
             * customer would see "certificate issued" and never receive anything,
             * which is the failure this step exists to remove.
             *
             * The licence key is deliberately absent from that message. This is the
             * one email a customer is expected to forward to a buyer, and putting a
             * bearer credential in it would hand the paid tier to their reviewers.
             */
            const account = loadAccount();
            const certMail = await deliverCertificate({
                entry: issued.entry,
                to: account?.email ?? "",
                certificateHtml: file,
            });
            if (certMail.status === "sent") {
                console.log("");
                console.log(`  Certificate emailed to ${account?.email ?? ""}`);
            }
            else if (certMail.status === "failed") {
                console.log("");
                console.log(`  Certificate NOT emailed: ${certMail.error}`);
                console.log(`  The record is issued and on disk either way.`);
            }
            // Badges are written alongside, unprompted. A customer who has to run a
            // second command for the social card will not run it, and the social card
            // is the only artefact here that travels to people who were not looking.
            depositCredential(issued.entry);
            const badges = writeBadges(path.dirname(issued.recordPath), issued.entry, {
                ...(args.repoId ? { repository: args.repoId } : {}),
            });
            console.log("");
            console.log(`  badges  ${path.dirname(badges.svg)}`);
            console.log(`    proofwork-badge.svg          README / site footer`);
            console.log(`    proofwork-badge-social.html  LinkedIn — print to PDF, already 1200x630`);
            console.log(`    proofwork-badge.md           the snippet to paste`);
            console.log("");
            console.log(`  For a PDF: open certificate.html or the social card and print to PDF.`);
        }
        catch (e) {
            // A missing private key means this is a customer machine, which is normal
            // and not an error. Reported rather than swallowed so an operator who
            // expected a record knows why there is not one.
            console.log("");
            console.log(`  No registry record issued: ${e instanceof Error ? e.message : String(e)}`);
            console.log(`  (Records are signed on the issuer's machine only.)`);
        }
        process.exit(0);
    }
    if (args.command === "verify") {
        if (!args.recordFile) {
            process.stderr.write("Usage: proofwork verify <record.json>\n");
            process.exit(1);
        }
        const raw = fs.readFileSync(args.recordFile, "utf8");
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch {
            process.stderr.write("Not JSON.\n");
            process.exit(1);
        }
        if (parsed.schema === CONDUCT_SCHEMA) {
            const pub = issuerPublicKey();
            if (!pub) {
                process.stderr.write("No issuer public key — cannot verify a conduct packet.\n");
                process.exit(1);
            }
            const result = verifyConductFile(args.recordFile, pub);
            if (args.json)
                process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
            else
                process.stdout.write(result.summary);
            process.exit(result.ok ? 0 : 1);
        }
        const result = verifyCredentialFile(args.recordFile);
        /**
         * Whether the record still describes the code here.
         *
         * Reported alongside the signature, never folded into it. A stale record is
         * signed, valid, and earned — it describes a state you are no longer looking
         * at, which is a different fact from "this did not verify" and calls for a
         * different response. Failing the exit code on it would tell people a
         * genuine certificate had been rejected.
         *
         * Only attempted when the record actually verified; there is nothing useful
         * to say about the currency of a record that is not authentic.
         */
        const freshness = result.entry ? assessFreshness(result.entry, args.root) : null;
        if (args.json) {
            process.stdout.write(`${JSON.stringify({ ...result, freshness, scope: result.entry ? scopeSentence(result.entry) : null }, null, 2)}\n`);
        }
        else {
            process.stdout.write(result.summary);
            if (freshness && result.ok) {
                process.stdout.write(`  Covers      ${freshnessLabel(freshness.state)} — ${freshness.note}\n` +
                    `  Scope       ${scopeSentence(result.entry)}\n\n`);
            }
        }
        process.exit(result.ok ? 0 : 1);
    }
    /**
     * Deposit a passing CI run, so a record is issued with nobody here involved.
     *
     * Only ever run by our reusable workflow. It grades, and on a pass it asks
     * GitHub to attest which workflow produced the result, then sends counts and
     * digests — never source, never findings — to the issuer.
     *
     * Every failure exits 0. This runs after the gate has already decided whether
     * to block the merge, and a certificate that could not be issued is not a
     * reason to fail a build that passed. The reason is printed either way.
     */
    if (args.command === "ci-deposit") {
        const issuerUrl = process.env.PROOFWORK_ISSUER_URL ?? DEPOSIT_AUDIENCE;
        // Trimmed before it is used anywhere. A licence pasted into a CI secret
        // arrives with whatever the editor or shell added — most often a leading
        // byte-order mark, which is invisible, survives every eyeball check, and is
        // not a legal HTTP header character. Untrimmed it produced "the character at
        // index 0 has a value of 65279", which tells a customer nothing at all.
        // `trim` covers U+FEFF as well as ordinary whitespace.
        const licenceKey = (process.env.PROOFWORK_LICENSE ?? "").trim();
        const repository = process.env.GITHUB_REPOSITORY ?? "";
        const note = (s) => {
            process.stdout.write(s);
        };
        if (!licenceKey) {
            note("\n  No PROOFWORK_LICENSE, so no record was requested.\n" +
                "  The gate still ran and its verdict stands.\n\n");
            process.exit(0);
        }
        const proof = runProof({ root: args.root, fast: args.fast, strict: args.strict });
        const score = scoreProof(proof);
        if (!proof.ok) {
            note("\n  Not a passing run — no record requested.\n\n");
            process.exit(0);
        }
        const oidc = await requestOidcToken({ audience: issuerUrl });
        if (!oidc.ok) {
            note(`\n  ${oidc.reason}\n\n`);
            process.exit(0);
        }
        const payload = buildDepositPayload({
            proof,
            subject: args.subject || repository.split("/")[1] || repository,
            score: score.final,
            assertions: score.assertions,
            repository,
            ...(process.env.GITHUB_SHA ? { commit: process.env.GITHUB_SHA } : {}),
            ...(process.env.GITHUB_REF_NAME ? { branch: process.env.GITHUB_REF_NAME } : {}),
        });
        const sent = await sendDeposit({ issuerUrl, payload, oidcToken: oidc.token, licenceKey });
        if (!sent.ok) {
            note(`\n  No record was issued: ${sent.reason}\n  The gate passed regardless.\n\n`);
            process.exit(0);
        }
        note(`\n  ${sent.status === "already_issued" ? "Record already issued" : "Record issued"} ` +
            `${sent.recordId}\n    ${sent.verifyUrl}\n\n`);
        // Surfaced in the run's summary so the link is where a reviewer looks.
        const summaryFile = process.env.GITHUB_STEP_SUMMARY;
        if (summaryFile) {
            try {
                fs.appendFileSync(summaryFile, `\n### Proofwork certificate\n\n` +
                    `**${sent.recordId}** · ${payload.integrity_score}/100\n\n` +
                    `[Verify this record](${sent.verifyUrl})\n`, "utf8");
            }
            catch {
                // A summary is a convenience. The record exists either way.
            }
        }
        process.exit(0);
    }
    /**
     * Send a record to the verify host so its link resolves for other people.
     *
     * Publication is opt-in and separate from issuance, because they answer to
     * different people. Issuing is ours; deciding that a third party may look this
     * up is the holder's. A gate that published every record automatically would
     * put a customer's denials on our infrastructure without asking.
     *
     * Nothing about the record changes. The signature already made it verifiable
     * offline by anyone holding the file; this only means a stranger with the link
     * does not need the file first.
     */
    if (args.command === "publish") {
        if (!args.recordFile) {
            process.stderr.write("\n  Usage: proofwork publish <record.json>\n\n" +
                "  Sends a signed record to the verify host so /verify/<id> resolves.\n" +
                `  Set ${VERIFY_HOST_ENV} to the host first.\n\n`);
            process.exit(1);
        }
        const host = verifyHost();
        if (!host) {
            process.stderr.write(`\n  ${VERIFY_HOST_ENV} is not set, so there is nowhere to publish to.\n\n` +
                `    ${VERIFY_HOST_ENV}=https://your-verify-host proofwork publish ${args.recordFile}\n\n` +
                "  The record is already verifiable offline by anyone you hand it to:\n" +
                `    proofwork verify ${args.recordFile}\n\n`);
            process.exit(1);
        }
        let body;
        try {
            body = fs.readFileSync(args.recordFile, "utf8");
        }
        catch (e) {
            process.stderr.write(`\n  Cannot read ${args.recordFile}: ${e instanceof Error ? e.message : String(e)}\n\n`);
            process.exit(1);
        }
        // Checked here as well as at the host. Publishing a record that does not
        // verify would fail anyway, and finding that out locally names the problem
        // as the file rather than as the network.
        const local = verifyCredentialFile(args.recordFile);
        if (!local.ok) {
            process.stderr.write(`\n  ${args.recordFile} does not verify, so there is no point publishing it.\n` +
                local.errors.map((e) => `    · ${e}\n`).join("") +
                "\n");
            process.exit(1);
        }
        void fetch(`${host}/records`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
            signal: AbortSignal.timeout(30_000),
        })
            .then(async (res) => {
            const j = (await res.json().catch(() => ({})));
            if (res.ok) {
                const id = j.record_id ?? local.entry?.record_id ?? "";
                process.stdout.write((j.status === "already_published"
                    ? `\n  Already published — ${id}\n`
                    : `\n  Published ${id}\n`) + `\n    ${host}/verify/${id}\n\n`);
                process.exit(0);
            }
            process.stderr.write(`\n  The host refused it: ${j.reason ?? `HTTP ${res.status}`}\n\n`);
            process.exit(1);
        })
            .catch((e) => {
            process.stderr.write(`\n  Could not reach ${host}: ${e instanceof Error ? e.message : String(e)}\n\n` +
                "  The record is unaffected and still verifies offline.\n\n");
            process.exit(1);
        });
        return;
    }
    if (args.command === "revoke") {
        /**
         * Issuer-only. Withdrawing a record needs the private key, for the same
         * reason issuing does: a revocation anyone can publish is a denial-of-service
         * against every certificate we have ever signed.
         */
        if (args.revokeList) {
            const list = readRevocationList();
            if (args.json)
                process.stdout.write(`${JSON.stringify(list, null, 2)}\n`);
            else
                process.stdout.write(renderRevocationList(list));
            process.exit(0);
        }
        const keys = loadOrCreateIssuerKeys();
        if (args.republish) {
            const list = republishRevocationList({
                privateKeyPem: keys.privateKeyPem,
                publicKeyPem: keys.publicKeyPem,
            });
            process.stdout.write(`\n  Republished list #${list.seq} · ${list.entries.length} withdrawal(s)\n` +
                `  Fresh until ${list.next_update.slice(0, 16).replace("T", " ")}\n\n`);
            process.exit(0);
        }
        if (!args.recordFile) {
            process.stderr.write("\n  Usage: proofwork revoke <PW-XXXX-XXXX-XXXX> --reason \"why\"\n" +
                "         proofwork revoke --list\n" +
                "         proofwork revoke --republish\n\n");
            process.exit(1);
        }
        if (!args.reason.trim()) {
            // A withdrawal with no stated reason reads as an accusation to whoever
            // checks the certificate, and they are usually not the party at fault.
            process.stderr.write("\n  --reason is required. It is shown to whoever checks the certificate,\n" +
                "  so write it for them.\n\n");
            process.exit(1);
        }
        const { list, alreadyRevoked } = revokeRecord({
            recordId: args.recordFile,
            reason: args.reason,
            privateKeyPem: keys.privateKeyPem,
            publicKeyPem: keys.publicKeyPem,
        });
        process.stdout.write(alreadyRevoked
            ? `\n  ${args.recordFile} was already withdrawn — nothing changed.\n\n`
            : `\n  Withdrawn ${args.recordFile}\n` +
                `  List #${list.seq} · ${list.entries.length} withdrawal(s)\n\n` +
                `  Publish the list where verifiers can reach it. Until it is published,\n` +
                `  only this machine knows.\n\n`);
        process.exit(0);
    }
    if (args.command === "certify") {
        const cert = runCertify({ root: args.root, maxCapacity: true });
        if (args.json) {
            process.stdout.write(`${JSON.stringify(cert, null, 2)}\n`);
        }
        else {
            console.log(cert.ok ? `Proofwork CERTIFY ${cert.tier.toUpperCase()}` : "Proofwork CERTIFY FAIL");
            console.log(cert.label);
            console.log(`badge: ${cert.badge_svg_path}`);
            console.log(`seal: ${cert.seal} · score=${cert.integrity_score}`);
            if (cert.reasons.length) {
                console.log("reasons:");
                for (const r of cert.reasons)
                    console.log(`  - ${r}`);
            }
        }
        process.exit(cert.tier === "certified" ? 0 : 2);
    }
    if (args.command === "share") {
        const { card, outPath, ok } = runShare(args.root);
        process.stdout.write(card);
        console.error(`Wrote ${outPath}`);
        process.exit(ok ? 0 : 2);
    }
    if (args.command === "explain") {
        const proof = runProof({ root: args.root, fast: true, strict: true });
        writeProofFiles(args.root, "", proof, true);
        process.stdout.write(explainProof(proof));
        process.exit(proof.ok ? 0 : 2);
    }
    if (args.command === "attest-verify") {
        const v = verifyAttestation(args.root);
        if (args.json) {
            process.stdout.write(`${JSON.stringify(v, null, 2)}\n`);
        }
        else {
            console.log(attestationPublicSummary(args.root));
            if (!v.ok) {
                console.log("errors:");
                for (const e of v.errors)
                    console.log(`  - ${e}`);
            }
        }
        process.exit(v.ok ? 0 : 2);
    }
    if (args.command === "fingerprints-reset") {
        const fp = path.join(args.root, ".proofwork", "deleted-fingerprints.json");
        if (fs.existsSync(fp)) {
            fs.unlinkSync(fp);
            console.log(`Removed ${fp}`);
        }
        else {
            console.log("No fingerprint store present — nothing to reset");
        }
        process.exit(0);
    }
    if (args.command === "summary") {
        if (!args.summaryIn || !fs.existsSync(args.summaryIn)) {
            console.error("summary requires --in <proof.json>");
            process.exit(1);
        }
        const proof = JSON.parse(fs.readFileSync(args.summaryIn, "utf8"));
        process.stdout.write(proofToMarkdown(proof));
        process.exit(0);
    }
    if (args.command === "ledger-add") {
        if (!args.ledgerName) {
            console.error("ledger add requires --name");
            process.exit(1);
        }
        const type = ["tool_call", "command", "note", "failure"].includes(args.ledgerType)
            ? args.ledgerType
            : "note";
        const ledger = appendLedgerEvent(args.root, {
            type,
            name: args.ledgerName,
            detail: args.ledgerDetail || undefined,
            fingerprint: args.ledgerFingerprint || undefined,
        });
        if (args.json) {
            process.stdout.write(`${JSON.stringify({ ok: true, events: ledger.events.length })}\n`);
        }
        else {
            console.log(`Ledger event appended (${ledger.events.length} total) → .proofwork/ledger.json`);
        }
        process.exit(0);
    }
    if (args.command !== "check") {
        console.error(`Unknown command: ${args.command}`);
        printHelp();
        process.exit(1);
    }
    runCheck(args);
}
// A rejected promise here would otherwise surface as an unhandled rejection with
// no context and exit 0 on some Node versions — a CLI that fails silently and
// reports success is the exact failure this project exists to catch.
main().catch((e) => {
    console.error(`proofwork: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
});
