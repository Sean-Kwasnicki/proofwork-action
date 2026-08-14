#!/usr/bin/env node
/**
 * Minimal MCP server for Proofwork — tools agents actually call.
 * Stdio JSON-RPC (MCP). No cloud.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appendLedgerEvent } from "./checks/spendLoop.js";
import { runProof } from "./run.js";
import { proofToAgentBrief, proofToMarkdown } from "./report.js";
import { runShare } from "./share.js";
const rootDefault = process.cwd();
function send(msg) {
    const body = JSON.stringify(msg);
    process.stdout.write(`Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`);
}
function ok(id, result) {
    send({ jsonrpc: "2.0", id, result });
}
function err(id, code, message) {
    send({ jsonrpc: "2.0", id, error: { code, message } });
}
const tools = [
    {
        name: "proofwork_check",
        description: "Run Proofwork Proof of Work checks and return the Proof JSON",
        inputSchema: {
            type: "object",
            properties: {
                root: { type: "string", description: "Repo root (optional)" },
                readiness_only: { type: "boolean" },
            },
        },
    },
    {
        name: "proofwork_status",
        description: "Fast low-token Proofwork brief (PASS/FAIL + blockers + timing). Prefer this for quick gates.",
        inputSchema: {
            type: "object",
            properties: { root: { type: "string" } },
        },
    },
    {
        name: "proofwork_doctor",
        description: "Run fast Proof and return brief plus fix hints for fails/warns",
        inputSchema: {
            type: "object",
            properties: { root: { type: "string" } },
        },
    },
    {
        name: "proofwork_ledger_add",
        description: "Record a failed command/tool into the Proofwork loop ledger",
        inputSchema: {
            type: "object",
            properties: {
                name: { type: "string" },
                detail: { type: "string" },
                fingerprint: { type: "string" },
                root: { type: "string" },
            },
            required: ["name"],
        },
    },
    {
        name: "proofwork_latest",
        description: "Read the latest Proof JSON from .proofwork/latest.json",
        inputSchema: {
            type: "object",
            properties: { root: { type: "string" } },
        },
    },
    {
        name: "proofwork_share",
        description: "PR-ready Proofwork card (CERTIFIED/DENIED). Agents should paste this on the PR — not narrate done.",
        inputSchema: {
            type: "object",
            properties: { root: { type: "string" } },
        },
    },
];
async function handleTool(name, args = {}) {
    const root = path.resolve(args.root || rootDefault);
    if (name === "proofwork_check" || name === "proofwork_status" || name === "proofwork_doctor") {
        const proof = runProof({
            root,
            readinessOnly: Boolean(args.readiness_only),
            fast: true,
        });
        const dir = path.join(root, ".proofwork");
        fs.mkdirSync(dir, { recursive: true });
        const compact = JSON.stringify(proof);
        fs.writeFileSync(path.join(dir, "latest.json"), `${compact}\n`);
        fs.writeFileSync(path.join(dir, "latest.md"), proofToMarkdown(proof));
        const brief = proofToAgentBrief(proof);
        fs.writeFileSync(path.join(dir, "latest-brief.txt"), `${brief}\n`);
        if (name === "proofwork_status") {
            return { content: [{ type: "text", text: brief }] };
        }
        if (name === "proofwork_doctor") {
            const hints = [brief, ""];
            for (const c of proof.checks) {
                if (c.status !== "fail" && c.status !== "warn")
                    continue;
                hints.push(`[${c.status}] ${c.id}: ${c.detail}`);
            }
            if (hints.length === 2)
                hints.push("All clear.");
            return { content: [{ type: "text", text: hints.join("\n") }] };
        }
        return { content: [{ type: "text", text: compact }] };
    }
    if (name === "proofwork_ledger_add") {
        if (!args.name)
            throw new Error("name is required");
        const ledger = appendLedgerEvent(root, {
            type: "failure",
            name: String(args.name),
            detail: args.detail ? String(args.detail) : undefined,
            fingerprint: args.fingerprint ? String(args.fingerprint) : undefined,
        });
        return {
            content: [{ type: "text", text: JSON.stringify({ ok: true, events: ledger.events.length }) }],
        };
    }
    if (name === "proofwork_latest") {
        const p = path.join(root, ".proofwork", "latest.json");
        if (!fs.existsSync(p)) {
            return { content: [{ type: "text", text: "No latest proof. Run proofwork_check first." }], isError: true };
        }
        return { content: [{ type: "text", text: fs.readFileSync(p, "utf8") }] };
    }
    if (name === "proofwork_share") {
        const { card, ok } = runShare(root);
        return { content: [{ type: "text", text: card }], isError: !ok };
    }
    throw new Error(`Unknown tool: ${name}`);
}
let buffer = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
        const headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd === -1)
            break;
        const header = buffer.slice(0, headerEnd).toString("utf8");
        const match = /Content-Length:\s*(\d+)/i.exec(header);
        if (!match) {
            buffer = buffer.slice(headerEnd + 4);
            continue;
        }
        const len = Number(match[1]);
        const start = headerEnd + 4;
        if (buffer.length < start + len)
            break;
        const body = buffer.slice(start, start + len).toString("utf8");
        buffer = buffer.slice(start + len);
        let msg;
        try {
            msg = JSON.parse(body);
        }
        catch {
            continue;
        }
        void onMessage(msg);
    }
});
async function onMessage(msg) {
    const { id, method, params } = msg;
    try {
        if (method === "initialize") {
            ok(id, {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: "proofwork", version: "0.10.0" },
            });
            return;
        }
        if (method === "notifications/initialized" || method === "initialized") {
            return;
        }
        if (method === "tools/list") {
            ok(id, { tools });
            return;
        }
        if (method === "tools/call") {
            const name = params?.name;
            if (!name)
                throw new Error("tools/call requires params.name");
            const args = (params?.arguments ?? {});
            const result = await handleTool(name, args);
            ok(id, result);
            return;
        }
        if (method === "ping") {
            ok(id, {});
            return;
        }
        if (id !== undefined)
            err(id, -32601, `Method not found: ${method}`);
    }
    catch (e) {
        if (id !== undefined)
            err(id, -32000, e instanceof Error ? e.message : String(e));
    }
}
const __dirname = path.dirname(fileURLToPath(import.meta.url));
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
    process.stderr.write("proofwork MCP server listening on stdio\n");
}
