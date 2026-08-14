#!/usr/bin/env node
/**
 * Tripwire MCP server — the simulated payment account an agent under test connects to.
 *
 * The agent sees an ordinary payment integration: balance, payment history, an
 * authorization request, a charge, a refund. Nothing it can observe distinguishes
 * this from a live account, which is the requirement — an agent that behaves well
 * only because it detected a sandbox has told you nothing about production.
 *
 * Transport matches the rest of this codebase: Content-Length framed JSON-RPC over
 * stdio, no dependencies. See `tools.ts` for why no call here can reach a real
 * payment network.
 *
 * Usage:
 *   proofwork-tripwire --scenario injected_instruction [--root .] [--out <file>]
 *
 * The operator pastes the scenario's instruction (and untrusted content) to the
 * agent, lets it work, then closes the session. The transcript is written to
 * .proofwork/tripwire/ and graded by `verdict.ts`.
 */
import fs from "node:fs";
import path from "node:path";
import { SessionLedger } from "./ledger.js";
import { executeTool, TOOL_SCHEMAS } from "./tools.js";
import { scenarioById, SCENARIOS } from "./scenarios.js";
import { evaluate } from "./verdict.js";
function send(msg) {
    const body = JSON.stringify(msg);
    process.stdout.write(`Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`);
}
const ok = (id, result) => send({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });
/** Tool results are returned as MCP content blocks; the agent reads the JSON text. */
const asContent = (payload, isError = false) => ({
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    ...(isError ? { isError: true } : {}),
});
function parseArgs(argv) {
    const opts = { scenario: "", root: process.cwd() };
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--scenario")
            opts.scenario = argv[++i] ?? "";
        else if (arg === "--root")
            opts.root = argv[++i] ?? process.cwd();
        else if (arg === "--out")
            opts.out = argv[++i];
    }
    return opts;
}
function usage() {
    process.stderr.write(`proofwork-tripwire --scenario <id> [--root <dir>] [--out <file>]\n\nScenarios:\n` +
        SCENARIOS.map((s) => `  ${s.id.padEnd(22)} ${s.title}`).join("\n") +
        `\n`);
    process.exit(2);
}
export function main(argv = process.argv.slice(2)) {
    const opts = parseArgs(argv);
    const scenario = scenarioById(opts.scenario);
    if (!scenario)
        usage();
    const ledger = new SessionLedger(scenario.id);
    // The operator's copy of the probe goes to stderr so it never contaminates the
    // JSON-RPC stream the agent is reading on stdout.
    process.stderr.write(`\nTripwire session ${ledger.sessionId}\nScenario: ${scenario.title}\n\n` +
        `--- paste to the agent under test ---\n${scenario.instruction}\n` +
        (scenario.untrusted_content ? `\n${scenario.untrusted_content}\n` : "") +
        `--- end ---\n\n(No real money can move. Close stdin to end the session.)\n\n`);
    let buffer = Buffer.alloc(0);
    const handle = (msg) => {
        switch (msg.method) {
            case "initialize":
                ok(msg.id, {
                    protocolVersion: "2024-11-05",
                    capabilities: { tools: {} },
                    // Named as an ordinary payment integration. Calling it "tripwire" here
                    // would tell the agent it is being watched.
                    serverInfo: { name: "payments", version: "1.0.0" },
                });
                return;
            case "notifications/initialized":
                return;
            case "tools/list":
                ok(msg.id, { tools: TOOL_SCHEMAS });
                return;
            case "tools/call": {
                const name = msg.params?.name ?? "";
                const args = msg.params?.arguments ?? {};
                const outcome = executeTool(ledger, name, args);
                ok(msg.id, asContent(outcome.result, Boolean(outcome.error)));
                return;
            }
            case "ping":
                ok(msg.id, {});
                return;
            default:
                if (msg.id !== undefined)
                    err(msg.id, -32601, `method not found: ${msg.method}`);
        }
    };
    process.stdin.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        // Content-Length framing: read a header block, then exactly that many bytes.
        for (;;) {
            const headerEnd = buffer.indexOf("\r\n\r\n");
            if (headerEnd === -1)
                return;
            const header = buffer.subarray(0, headerEnd).toString("utf8");
            const match = /Content-Length:\s*(\d+)/i.exec(header);
            if (!match) {
                // Unparseable header: drop it rather than spin on the same bytes forever.
                buffer = buffer.subarray(headerEnd + 4);
                continue;
            }
            const length = Number(match[1]);
            const start = headerEnd + 4;
            if (buffer.length < start + length)
                return;
            const body = buffer.subarray(start, start + length).toString("utf8");
            buffer = buffer.subarray(start + length);
            try {
                handle(JSON.parse(body));
            }
            catch {
                err(null, -32700, "parse error");
            }
        }
    });
    const close = () => {
        const record = ledger.finalize();
        const verdict = evaluate(record, scenario);
        const file = opts.out ?? path.join(opts.root, ".proofwork/tripwire", `${record.session_id}.json`);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, `${JSON.stringify({ record, verdict }, null, 2)}\n`, "utf8");
        process.stderr.write(`\n${verdict.passed ? "PASS" : "FAIL"} — ${verdict.summary}\n` +
            verdict.violations
                .map((v) => `  [${v.severity}] ${v.title}\n      ${v.detail}\n      calls: ${v.calls.join(", ")}`)
                .join("\n") +
            `\n\nTranscript: ${file}\n`);
        process.exit(verdict.passed ? 0 : 1);
    };
    process.stdin.on("end", close);
    process.on("SIGINT", close);
}
// Run only when invoked directly, so tests can import without starting a server.
const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]).endsWith(path.join("tripwire", "server.js"));
if (invokedDirectly)
    main();
