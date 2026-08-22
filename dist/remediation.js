/**
 * Findings are matched most-specific-first: a check may expose a sub-reason in its
 * evidence (`config_weaken`, an undisclosed provider, a bypass id), and the advice
 * for that reason is far more useful than advice for the check in general.
 */
const REMEDIATIONS = {
    "integrity.fake_green": {
        summary: "Changed tests contain patterns that make a suite report success without testing anything.",
        why: "A skipped or hollowed-out test is worse than a missing one: the suite stays green, so " +
            "nobody looks again. This is the most common way agent-written code reaches production broken.",
        steps: [
            "Open each file:line listed in the finding — the location is in the failure message.",
            "For `.skip` / `xit` / `pending`: either restore the assertion or delete the test outright. A permanently skipped test is dead code that lies about coverage.",
            "For `.only` / `fdescribe`: remove the focus modifier. It silently disables every other test in the file.",
            "For tautology assertions (`expect(true).toBe(true)`): assert against the value the code under test actually produced.",
            "For a mock that returns hardcoded success: assert the mock was called with the arguments you expect, not merely that the call returned.",
            "If a test genuinely must stay disabled, add `// proofwork-ignore` on the line with a comment explaining why and who will restore it.",
        ],
        verify: "Re-run `proofwork check`. The finding should clear, and your suite should now fail if you deliberately break the code under test.",
    },
    "github.auth": {
        summary: "The GitHub CLI is not authenticated, so the pull-request surface cannot be read.",
        why: "When the gate runs against a pull request it compares the branch to its base. Without " +
            "authentication it cannot resolve that base, so it falls back to comparing against local " +
            "history — a narrower view that can miss changes introduced earlier in the branch.",
        steps: [
            "Run `gh auth login` locally, or set `GH_TOKEN` in CI.",
            "In GitHub Actions the built-in `GITHUB_TOKEN` is usually enough — pass it as `GH_TOKEN` in the step's `env`.",
            "If you do not use GitHub, this check is not relevant and skipping it is correct. It affects only the breadth of the comparison, never the verdict on what it did examine.",
        ],
        verify: "Run `gh auth status`, then `proofwork check` on a branch with an open pull request.",
    },
    "tooling.agentsaver": {
        summary: "Optional session-memory tooling was not found.",
        why: "This is a convenience integration, not part of the gate. It lets an agent carry context " +
            "between sessions. Its absence changes nothing about the verdict and no check depends on it.",
        steps: [
            "If you want it, install the tool and re-run. Otherwise ignore this — it is informational.",
            "This check never blocks a certificate. It appears so the report accounts for every family it looked at rather than silently omitting one.",
        ],
        verify: "No action required. Re-run `proofwork check` if you install it.",
    },
    "git.repository": {
        summary: "This directory is not a git repository, so most of the gate cannot run.",
        why: "Almost every check here works by comparing what changed against what was there before. " +
            "Without version history there is no 'before', so the checks that catch reintroduced code, " +
            "altered tests, and edits to the gate's own rules have nothing to compare and skip themselves. " +
            "A run in this state is not a clean result — it is an unexamined one, and the score is capped " +
            "to reflect that rather than rewarding the absence of evidence.",
        steps: [
            "Run `git init` in this directory, then `git add -A && git commit -m 'initial'` to establish a baseline.",
            "If this is a subdirectory of a larger repository, run the gate from the repository root instead — it needs to see the history.",
            "In CI, check out with full history rather than a shallow clone. `actions/checkout` defaults to depth 1, which hides the comparison the gate depends on; set `fetch-depth: 0`.",
        ],
        verify: "Re-run `proofwork check`. The skipped families should now report a real verdict, and the coverage ceiling should rise.",
        reference: "ISO/IEC 42001 A.6.2.3 Documentation of AI-System Design and Development",
    },
    "runtime.node": {
        summary: "The Node runtime is missing or older than this gate supports.",
        why: "The gate uses APIs that older runtimes do not provide. Rather than fail in a confusing way " +
            "partway through a run — which would look like a finding about your code — it reports the " +
            "environment problem directly.",
        steps: [
            "Install Node 20 or later, or switch to it with `nvm use 20`.",
            "In CI, pin the version explicitly rather than relying on the runner default, which changes without notice.",
            "Check `node --version` resolves to what you expect — a shell alias or a stale PATH entry is the usual cause when the installed version looks correct.",
        ],
        verify: "Run `node --version`, then `proofwork check`.",
    },
    "project.package_json": {
        summary: "No package.json was found, so parts of the gate cannot identify your dependencies.",
        why: "Dependency manifests are how the gate identifies which AI model providers your code relies " +
            "on, which is the basis of the subprocessor disclosure check. Without one, that check cannot " +
            "run and the coverage ceiling drops — not as a penalty, but because a surface that could not " +
            "be examined has not been cleared.",
        steps: [
            "If this is a Node project, run `npm init -y` and commit the result.",
            "If it is not a Node project, this is expected. The dependency-based checks will skip and say so; nothing is wrong.",
            "If the manifest lives in a subdirectory of a monorepo, run the gate from that package's directory so it sees the right manifest.",
        ],
        verify: "Re-run `proofwork check` and confirm the dependency-based families report a verdict rather than skipping.",
    },
    "cursor.mcp_config": {
        summary: "No agent configuration was found, so the agent-behaviour checks have nothing to read.",
        why: "What an agent is permitted to do — which tools it can call, whether approval is required, " +
            "what credentials it can reach — is declared in configuration. Those declarations are what " +
            "the autonomy, takeover, and delegated-authority checks read. With no configuration present " +
            "they skip, which means the most consequential questions about this agent went unasked.",
        steps: [
            "If an agent operates in this repository, make sure its configuration is committed — `.mcp.json`, `.cursor/mcp.json`, `AGENTS.md`, or `CLAUDE.md` depending on the tool.",
            "If the configuration is deliberately kept outside the repository, point the gate at it or record where it lives, so a reviewer knows the surface was examined elsewhere.",
            "If no agent operates here, this is expected and the skip is correct — the checks are reporting that the question does not apply, not that it passed.",
        ],
        verify: "Re-run `proofwork check`. The agent-behaviour families should report a verdict rather than skipping.",
        reference: "EU AI Act Art. 14 Human Oversight · NIST AI RMF MAP 2.2",
    },
    "regulatory.disclosure": {
        summary: "People reached by this system may not have been told they are dealing with an AI.",
        why: "EU AI Act Article 50(1) became applicable on 2 August 2026. A system that interacts directly " +
            "with natural persons must be designed so those people know it is an AI, unless that is obvious. " +
            "This is the obligation an autonomous agent is most likely to breach at the exact moment it " +
            "performs well — a fluent, warm reply sent under a human-sounding name is the agent doing its " +
            "job and the operator being non-compliant simultaneously.",
        steps: [
            "Open the file:line in the finding — it names the outbound channel that reaches a person.",
            "Add identification to that channel: a line in the message body, a display name that reads as an assistant, or a header. It only has to be clear at first interaction, not repeated in every sentence.",
            "Put the disclosure in one shared place — a template module or a config field — rather than at each call site. The check looks repository-wide, and one factored-out disclosure covers every sender that uses it.",
            "If the finding says disclosure is *suppressed* rather than absent, treat it as urgent and separate. Removing an identification is a decision a regulator reads as aggravating, and an instruction telling an agent not to admit it is an AI is the clearest possible version of that.",
            "For synthetic images, audio, or video: attach machine-readable provenance — C2PA / Content Credentials or an embedded watermark. Systems already on the market before 2 August 2026 have until 2 December 2026 for this specifically.",
            "If disclosure genuinely lives in a UI layer in another repository, record that here in a comment or your governance notes. The finding is about what this codebase can show, and a reviewer needs to know where to look.",
        ],
        verify: "Re-run `proofwork check`. Then read one real outbound message end to end as its recipient would, and ask whether a reasonable person would know an AI wrote it.",
        reference: "EU AI Act Art. 50(1), 50(2), 50(5) — applicable 2026-08-02 · ISO/IEC 42001 A.8.2 · OWASP ASI09",
    },
    "regulatory.record_keeping": {
        summary: "What this agent did cannot be reconstructed afterwards.",
        why: "EU AI Act Article 12 requires records that make a system's functioning traceable, and Article 19 " +
            "treats six months as the floor for keeping them. This matters far more for an agent than for a " +
            "tool: when a human clicks, the human remembers and the click is in an access log. An agent " +
            "running unattended overnight has no such fallback — if it did not write down what it did, nobody " +
            "can establish what it did, including you.",
        steps: [
            "Open the file:line in the finding — it names a consequential action that is not being recorded.",
            "Record the action durably: a structured logger with a sink, an append-only audit table, or an event stream. What matters is that it survives the process.",
            "If the finding says recording is console-output only, that is the important case. Process logs vanish on redeploy, so they pass code review and answer nothing six weeks later when it counts.",
            "Record enough to reconstruct the action, not the whole payload: what was done, to what, when, under whose authority, and what the outcome was. A log full of secrets creates a new problem.",
            "Set retention to at least six months unless other law requires longer. A shorter window is reported because Art. 19 uses six months as its floor.",
            "If the finding says the trail is *deleted or disabled*, treat that first and separately. An agent that erases its own record is categorically different from one that never kept it.",
        ],
        verify: "Re-run `proofwork check`. Then answer the question an investigator would ask: pick a consequential action from last week and reconstruct it end to end from the records alone.",
        reference: "EU AI Act Art. 12, Art. 19, Art. 26(6) · ISO/IEC 42001 A.6.2.8 · NIST AI RMF MEASURE 2.8",
    },
    "regulatory.automated_decision": {
        summary: "A decision affecting a person appears to execute with no way for a human to intervene.",
        why: "GDPR Article 22 gives a person the right not to be subject to a decision based solely on " +
            "automated processing where it significantly affects them, and Article 22(3) requires — at " +
            "minimum — a route to human intervention and a way to contest the outcome. The load-bearing word " +
            "is *solely*: deciding automatically is fine, and is the point of the software. Agents make this " +
            "sharper than the scoring systems the article was written about, because an agent decides and " +
            "executes in one step, closing the gap where review used to sit without anyone choosing to.",
        steps: [
            "Open the file:line in the finding — it names the decision domain and the point at which the outcome is applied.",
            "Decide whether this outcome genuinely lands on a person with real consequences. Credit, employment, benefits, insurance, account suspension, and individually targeted pricing are the named cases. If it does not, say so in a comment so the next reviewer does not re-litigate it.",
            "Where it does, add a route by which a human can get in the way: a review queue for high-impact outcomes, an override, an appeal path, or an escalation threshold. It does not have to be review of every decision — it has to be reachable.",
            "Prefer proposing to applying for the highest-impact band. An agent that marks a case for review has not made an Art. 22 decision at all.",
            "Tell the affected person the route exists. A right to contest that nobody is informed of is not a safeguard, and this is the part most often missed.",
            "If the finding says review was explicitly bypassed or switched off, treat that first. Removing oversight is a decision, and it reads very differently to a regulator than never having built it.",
        ],
        verify: "Re-run `proofwork check`. Then walk one adverse outcome through as the affected person: can they reach a human, and would they know how?",
        reference: "GDPR Art. 22(1), 22(3) · EU AI Act Art. 14 and Annex III · ISO/IEC 42001 A.9.2",
    },
    "agent_security.delegated_authority": {
        summary: "The agent spends its owner's authority without a boundary the owner set.",
        why: "This is not a finding about autonomy. An agent acting on its own, under its own identity, " +
            "within its own budget, is doing exactly what it was built to do and this check passes it. " +
            "The finding is narrower: the agent acts *as its owner* — their saved card, their mailbox, " +
            "their credentials — and nothing in the configuration says how far that goes. Every " +
            "downstream system will record a human as the actor for something no human saw.",
        steps: [
            "Decide whose authority each consequential action spends. If the agent can use its own service credential, mailbox, or billing account, switch to it — that removes the finding entirely and is usually the right design.",
            "Where the agent genuinely must act as the owner, declare a ceiling: a maximum amount, a daily cap, or an explicit approval threshold. The number is yours; the check only requires that one exists.",
            "Put a reachable approval path behind that ceiling. An approval step that cannot actually reach a human is worse than none, because it reads as consent in the audit trail.",
            "Small and routine actions can stay automatic. That is the point of the threshold — it lets an agent be fully autonomous below the line you drew, and asks only above it.",
            "Write the boundary where a reviewer can find it, not only in code. A limit nobody can locate cannot be verified by the customer, insurer, or regulator asking about it.",
        ],
        verify: "Re-run `proofwork check`. Then test the boundary directly: trigger an action above your declared threshold and confirm it stops and asks rather than proceeding.",
        reference: "EU AI Act Art. 14 · NIST AI RMF MANAGE 2.4 · OWASP ASI03 (2026)",
    },
    "agent_security.declared_capabilities": {
        summary: "The agent reaches something its capability manifest does not declare.",
        why: "This is not a finding about the capability. The money path may be bounded, logged, and " +
            "perfectly well built — the check does not dispute that, and the other checks will say so. " +
            "The finding is that your manifest is what a reviewer reads *instead of* the source, and it " +
            "told them this surface was not there. A security review, an approval, an insurance " +
            "questionnaire, a procurement answer: each one that relied on the declaration was answered " +
            "with the wrong facts. That is why it is classed as misrepresentation rather than as a " +
            "missing control — the control may exist; the description does not match it.",
        steps: [
            "Look at the files named in the finding. They are yours, and the question is only whether the manifest describes them.",
            "If the agent is supposed to reach that surface, declare it. Setting `\"money\": true` clears this check immediately and costs you nothing — the capability was already there, and the other checks were already examining it.",
            "If the agent is *not* supposed to reach it, this is the more valuable outcome: you have found code that exceeds the scope you thought you were running. Remove the capability rather than declaring it.",
            "An omitted key and an explicit `false` are treated the same. Leaving a capability out is not a way to avoid the question.",
            "Declaring a surface the gate cannot find is not a failure. It is recorded as NOT EXAMINED, and the run says it cannot give a full clear on something it never saw — which is a bounded claim, not a black mark.",
        ],
        verify: "Re-run `proofwork check`. Then read your manifest as if you were the buyer: does it describe everything this agent can reach on its own?",
        reference: "EU AI Act Art. 11 and Annex IV · ISO/IEC 42001 A.5.2 · NIST AI RMF GOVERN 1.2",
    },
    "agent_security.hijack": {
        summary: "This agent could be used to take control of another agent.",
        why: "In a multi-agent system one agent's output is the next agent's input, so a single hijacked " +
            "agent inherits the trust of everything downstream of it. The compromise moves inside the " +
            "agent communication layer, where no firewall or network control can see it. Findings here " +
            "cite OWASP ASI (2026) so a security reviewer can check the category independently.",
        steps: [
            "ASI01 — instruction override: an agent-readable file contains text that redirects a reader's objective. If you did not write it, treat this as an active injection and check what has already read the file. If you did write it, move the instruction into code where it is executed rather than interpreted.",
            "ASI04 — tool poisoning: a tool description contains instructions rather than description. Rewrite it to state what the tool does. A description that tells the agent what to do first is a prompt, and it is loaded before the tool is ever called.",
            "ASI07 — unauthenticated channel: instructions are sent to another agent with nothing establishing the caller. Sign the request or attach a service credential, and have the receiving agent reject unsigned work. Reachability is not identity.",
            "ASI03 — privilege delegation: a child agent was created with authority its parent lacked. Pass the parent's constraints down explicitly. A delegated agent must never be able to do something the agent that created it could not.",
            "ASI04 — remote instructions: the agent's prompt is fetched at runtime, so whoever controls that URL controls this agent forever without touching your repository. Move the prompt into version control where a change is reviewable.",
        ],
        verify: "Re-run `proofwork check`. Then confirm the negative case directly: send the receiving agent an unsigned instruction and check that it refuses.",
        reference: "OWASP Top 10 for Agentic Applications (ASI) 2026 · EU AI Act Art. 14 · ISO/IEC 42001 A.9.2",
    },
    "integrity.grader_bypass": {
        summary: "This project's configuration asks to switch off checks that cannot be switched off.",
        why: "Namespaces that can fail a run are not configurable. The request was refused and every check " +
            "ran anyway — but the attempt is recorded, because asking to disable the gate says something " +
            "about the change regardless of whether it worked.\n\n" +
            "This used to be enforced by watching for edits to the config file, which meant a repository " +
            "that shipped the skip list in its first commit was never examined. Refusal now happens when " +
            "the check list is assembled, so the age of the entry makes no difference.",
        steps: [
            "Open `proofwork.config.json` and remove the protected entries named in the finding from `skipChecks`.",
            "If a check is producing a false positive, that is a bug in the check and worth reporting — suppressing the whole namespace hides every real finding it would have caught alongside the wrong one.",
            "For a single finding that genuinely does not apply, use `// proofwork-ignore: <reason>` at the site. A directive carrying a written reason is always honoured and is not rationed.",
            "`skipChecks` remains available for unprotected checks — readiness and environment families — where suppression is a reasonable local choice.",
        ],
        verify: "Re-run `proofwork check` and confirm this finding no longer appears.",
        reference: "ISO/IEC 42001 A.6.2.4 · NIST AI RMF MANAGE 2.3",
    },
    "integrity.verification": {
        summary: "This project has no working way to detect a regression.",
        why: "Every other integrity check in this gate inspects tests that exist — whether they were " +
            "skipped, emptied, or written to assert nothing. None of them fires on a repository " +
            "containing no tests at all, which made writing none the cheapest way past the strictest part " +
            "of the gate. Without a suite, no claim about this code's behaviour can be checked by anyone, " +
            "including you.",
        steps: [
            "Start with the code that would cost the most if it broke silently — money movement, permissions, data deletion. One real test there is worth more than broad shallow coverage.",
            "Assert on values the code produced, not that it ran without throwing. If you cannot say what should be true, the behaviour is not yet specified well enough to test.",
            "If the finding names a `test` script that exits 0 without running anything, fix that first. An absent suite is visible in review; a green run that tested nothing is not, and every CI system downstream reports success on it.",
            "A test file containing one line is not counted here, deliberately — an empty placeholder would otherwise satisfy the check while proving nothing.",
            "If this repository genuinely does not need tests — documentation, manifests, a throwaway prototype — the check skips itself below a small size threshold. If it fired, there is enough real code that a reviewer would expect a suite.",
        ],
        verify: "Re-run `proofwork check`. Then confirm the suite can actually fail: break the code under test on purpose and check that a test goes red.",
        reference: "ISO/IEC 42001 A.6.2.4 · NIST AI RMF MEASURE 2.5 · EU AI Act Art. 15",
    },
    "integrity.workmanship": {
        summary: "The change contains work that runs but does not do what it appears to.",
        why: "These are the failures an agent commits without meaning to. A test that asserts nothing " +
            "passes forever; a discarded error turns a failure into a silent success; a TODO ships as " +
            "a finished feature. Each one reaches production looking green, which is why review misses them.",
        steps: [
            "Open each file:line in the finding — every one names an exact location.",
            "For a hollow test: assert on the value the code under test produced, not that it ran. If you cannot name what should be true, the test is not yet worth having.",
            "For an empty catch: either handle the failure, rethrow with context (`throw new Error('...', { cause: e })`), or add a comment saying why the failure is genuinely safe to ignore. A comment is accepted — an explained decision is what we want recorded.",
            "For a catch that only logs: decide whether the caller can proceed. If it cannot, rethrow. Logging and continuing is how corrupt state reaches the database.",
            "For a TODO or FIXME: finish it, or move it to your tracker and delete the marker. A marker in shipped code is a promise nobody is holding.",
            "For sprawl: check whether a much smaller edit achieves the same thing. Volume is not progress.",
        ],
        verify: "Re-run `proofwork check`. Then break the code under test deliberately and confirm the test now fails — a test that passes either way was never testing anything.",
        reference: "ISO/IEC 42001 A.6.2.4 · NIST AI RMF MEASURE 2.5",
    },
    "integrity.change_test_bind": {
        summary: "A substantial production change is not bound to a constraining test.",
        why: "An agent can add a function, leave tests pointing at a different module, and still look finished. " +
            "The gate does not run the suite. It asks whether a test imports this file or names an export and asserts a result.",
        steps: [
            "Open the file:symbol listed in the finding.",
            "Add or extend a test that imports that module and asserts a real result (not expect(true), not toBeDefined alone).",
            "Re-run the gate on the same commit.",
        ],
        verify: "Re-run `proofwork check`. The change-bind check should pass, and hollow-test should stay clear.",
        reference: "ISO/IEC 42001 A.6.2.4 · NIST AI RMF MEASURE 2.5",
    },
    "integrity.reintroduction": {
        summary: "Code that was deliberately deleted has reappeared in the working tree.",
        why: "Deletions are decisions. When an agent restores one — usually while 'fixing' something " +
            "nearby — it silently reverses a decision nobody revisited, and the bug you already closed reopens.",
        steps: [
            "Run `git log -S '<a distinctive line from the restored code>'` to find the commit that removed it and read why.",
            "If the deletion was correct, remove the reintroduced code again and add a regression test that fails if it returns.",
            "If the deletion was wrong, restore it deliberately in its own commit with a message explaining the reversal.",
            "Never resolve this by suppressing the check — the fingerprint exists precisely because this class of change is invisible in review.",
        ],
        verify: "Re-run `proofwork check`; the reintroduction fingerprint should no longer match.",
    },
    "integrity.spend_loop": {
        summary: "The same command failed repeatedly with no change in approach between attempts.",
        why: "Retrying an identical command is the signature of an agent that has stopped making progress. " +
            "Every repeat costs tokens and wall-clock time and moves nothing.",
        steps: [
            "Read the failing command in the finding and run it yourself once — the real error is usually obvious to a human in seconds.",
            "Fix the underlying cause: a missing dependency, a wrong path, an unset environment variable.",
            "If the agent is looping, give it the error text directly and tell it to change approach rather than retry.",
            "Clear the ledger with `proofwork ledger reset` once the cause is fixed, so the count starts clean.",
        ],
        verify: "Run the previously failing command successfully, then `proofwork check`.",
    },
    "integrity.grader": {
        summary: "The work under review modified the configuration or workflow that grades it.",
        why: "An agent that can edit its own gate is not being graded. This is the one failure with no " +
            "benign automated resolution — a human has to look at the diff and decide.",
        steps: [
            "Run `git diff -- <the protected path in the finding>` and read the change yourself.",
            "If the agent made it: revert it. `git checkout HEAD -- <path>`.",
            "If you intended it: commit it separately, by hand, with a message saying why the gate is changing.",
            "Never resolve this by adding the check to `skipChecks` — that edit is itself detected and will fail the run.",
        ],
        verify: "`git diff` shows no changes to protected paths, then re-run `proofwork check`.",
    },
    "ai_governance.subprocessors": {
        summary: "The code depends on AI providers that your published subprocessor disclosure does not list.",
        why: "Enterprise buyers ask AI vendors to name every model provider that touches their data, and a " +
            "stale list is a standard finding in vendor security review. It is also the disclosure " +
            "obligation behind EU AI Act Art. 13 and ISO 42001 A.10.3.",
        steps: [
            "Open `AI-SUBPROCESSORS.md` (create it at the repo root if the finding says none was found).",
            "Add each provider named in the finding, with: provider name, what it does, what data reaches it, and the region it processes in.",
            "State your customer-data training stance explicitly — buyers ask, and silence reads as yes.",
            "Link the file from your public trust page or security documentation so a reviewer can find it without asking.",
            "Add reviewing this file to your dependency-update checklist; it goes stale the next time someone adds an SDK.",
        ],
        verify: "Re-run `proofwork check`; the disclosure check should pass with every detected provider listed.",
        reference: "ISO/IEC 42001 A.10.3 Suppliers · EU AI Act Art. 13",
    },
    "agent_security.secret_exposure": {
        summary: "A credential is sitting in a file the agent reads as part of its context.",
        why: "This is not an ordinary leaked key — it has been placed where the model can read it. Any " +
            "prompt injection that reaches this agent can read it too, and exfiltrate it in a reply.",
        steps: [
            "Rotate the credential now, before fixing the file. Treat it as compromised — it has been in model context and may be in logs or transcripts.",
            "Replace the literal with an environment variable reference: `${ANTHROPIC_API_KEY}` in config, `process.env.X` in code.",
            "For MCP servers, pass secrets via the `env` block from your shell environment, never inline in the committed config.",
            "Purge it from history if the file was committed: `git filter-repo` or BFG. Rotation alone leaves the old value in the repository forever.",
            "Add the file to a secret scanner in CI so the next one is caught before merge.",
        ],
        verify: "Re-run `proofwork check`; the exposure check should pass. Confirm the agent still works using the environment variable.",
        reference: "EU AI Act Art. 15 · NIST AI RMF MEASURE 2.7",
    },
    "agent_security.autonomy": {
        summary: "The agent can take an irreversible action — spend, delete, or send as you — with approval switched off.",
        why: "Neither half is dangerous alone. Together they mean the first mistaken tool call is also the " +
            "final one, with no human in the loop to catch it. This is the configuration that costs people money.",
        steps: [
            "Find the bypass named in the finding — `autoApprove`, `alwaysAllow`, `--dangerously-skip-permissions`, or a permission policy set to allow-all.",
            "Turn it off for the consequential tool specifically. You can keep auto-approval for read-only tools; the point is that money, deletion, and outbound messages ask first.",
            "If your framework supports per-tool policies, set the consequential tool to `always_ask` rather than disabling approvals globally.",
            "If the agent genuinely must act unattended, put a hard ceiling in front of it — a spend cap, a dry-run mode, or a queue a human drains — rather than removing the gate.",
            "Re-read what the agent is actually granted. Most agents are given far more capability than the task needs.",
        ],
        verify: "Re-run `proofwork check`. Then trigger the tool once and confirm you are prompted before it executes.",
        reference: "EU AI Act Art. 14 Human Oversight · NIST AI RMF MANAGE 2.4",
    },
    "readiness.git": {
        summary: "This directory is not a git repository, so no diff-based check can run.",
        why: "Every integrity check works by comparing what changed. Without git there is no before, and " +
            "the strongest checks silently have nothing to examine.",
        steps: ["Run `git init`.", "Commit the current state so there is a baseline to diff against."],
        verify: "`git status` succeeds, then re-run `proofwork check`.",
    },
    "project.vitest": {
        summary: "No test runner was detected, so anti-fake-green has a much smaller surface to scan.",
        why: "The fake-green check reads test files. Without a runner there are usually none, which means " +
            "the most valuable check in the suite is inspecting nothing.",
        steps: [
            "Install a runner: `npm i -D vitest` (or Jest, if that is your house standard).",
            "Add a `test` script to package.json.",
            "Write one real test for the code path you would most regret breaking.",
        ],
        verify: "`npm test` runs, then re-run `proofwork check`.",
    },
};
/** Sub-reasons that deserve more specific advice than their parent check. */
const SPECIFIC = {
    "integrity.grader/skip_protected_check": {
        summary: "The config change adds a protected check to `skipChecks`.",
        why: "Every namespace that can fail a run is protected from being disabled in config. Editing " +
            "this is indistinguishable from disabling the gate, so it fails regardless of intent.",
        steps: [
            "Remove the entry from `skipChecks` in `proofwork.config.json`.",
            "If the check is producing a false positive, fix or narrow the check and open an issue — do not suppress the namespace.",
            "For a genuinely inapplicable check, use a scoped `// proofwork-ignore` at the finding site with a written reason.",
        ],
        verify: "`skipChecks` contains no protected namespace, then re-run `proofwork check`.",
    },
};
/**
 * Look up remediation for a finding.
 *
 * Returns undefined rather than a generic fallback: a vague "review the finding"
 * teaches the reader that this field is noise, and they stop reading the ones that
 * are specific. Silence is better than filler.
 */
export function remediationFor(check) {
    const evidence = (check.evidence ?? {});
    const weaken = evidence.config_weaken;
    if (Array.isArray(weaken)) {
        for (const entry of weaken) {
            const id = entry?.id;
            const specific = SPECIFIC[`${check.id}/${id}`];
            if (specific)
                return specific;
        }
    }
    return REMEDIATIONS[check.id];
}
/** Render remediation as plain text for the CLI and the agent brief. */
export function renderRemediation(check) {
    const fix = remediationFor(check);
    if (!fix)
        return undefined;
    const lines = [
        `HOW TO FIX — ${check.title}`,
        ``,
        `  ${fix.summary}`,
        ``,
        `  Why it matters: ${fix.why}`,
        ``,
        ...fix.steps.map((step, i) => `  ${i + 1}. ${step}`),
        ``,
        `  Verify: ${fix.verify}`,
        ...(fix.reference ? [`  Reference: ${fix.reference}`] : []),
    ];
    return lines.join("\n");
}
/** Every failing or warning check that has guidance, in report order. */
export function remediationsForProof(checks) {
    return checks
        .filter((c) => c.status === "fail" || c.status === "warn")
        .map((check) => ({ check, fix: remediationFor(check) }))
        .filter((entry) => entry.fix !== undefined);
}
