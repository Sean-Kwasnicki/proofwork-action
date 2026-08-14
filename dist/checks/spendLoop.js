import fs from "node:fs";
import path from "node:path";
const LEDGER_PATH = ".proofwork/ledger.json";
export function defaultLedger(taskId = "default") {
    return {
        version: 1,
        task_id: taskId,
        events: [],
        limits: { max_identical_failures: 3, max_events: 200 },
    };
}
export function loadLedger(root) {
    const p = path.join(root, LEDGER_PATH);
    if (!fs.existsSync(p))
        return defaultLedger();
    try {
        return JSON.parse(fs.readFileSync(p, "utf8"));
    }
    catch {
        return defaultLedger();
    }
}
export function saveLedger(root, ledger) {
    // Honours the same read-only contract as the fingerprint store: grading a
    // repository must be able to leave it exactly as it was found.
    if (process.env.PROOFWORK_READONLY === "1")
        return;
    const p = path.join(root, LEDGER_PATH);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
}
export function appendLedgerEvent(root, event) {
    const ledger = loadLedger(root);
    ledger.events.push({ ...event, at: new Date().toISOString() });
    if (ledger.events.length > ledger.limits.max_events) {
        ledger.events = ledger.events.slice(-ledger.limits.max_events);
    }
    saveLedger(root, ledger);
    return ledger;
}
export function runSpendLoopChecks(root, opts = {}) {
    const ledger = loadLedger(root);
    const limit = opts.maxIdenticalFailures ?? ledger.limits.max_identical_failures;
    if (ledger.events.length === 0) {
        return [
            {
                id: "integrity.spend_loop",
                title: "Spend / loop ledger",
                status: "pass",
                detail: "No ledger events yet — agents should append failures via proofwork ledger add",
                evidence: { path: LEDGER_PATH, limit },
            },
        ];
    }
    const failFingerprints = ledger.events
        .filter((e) => e.type === "failure")
        .map((e) => e.fingerprint || `${e.name}|${e.detail ?? ""}`);
    const counts = new Map();
    for (const fp of failFingerprints) {
        counts.set(fp, (counts.get(fp) ?? 0) + 1);
    }
    let max = 0;
    let worst = "";
    for (const [fp, n] of counts) {
        if (n > max) {
            max = n;
            worst = fp;
        }
    }
    if (max >= limit) {
        return [
            {
                id: "integrity.spend_loop",
                title: "Spend / loop ledger",
                status: "fail",
                detail: `Identical failure repeated ${max} times (limit ${limit}): ${worst}`,
                evidence: { max, worst, events: ledger.events.length, limit },
            },
        ];
    }
    return [
        {
            id: "integrity.spend_loop",
            title: "Spend / loop ledger",
            status: "pass",
            detail: `Ledger OK — ${ledger.events.length} event(s); max identical failure streak ${max} (limit ${limit})`,
            evidence: { events: ledger.events.length, max_identical_failures: max, limit },
        },
    ];
}
