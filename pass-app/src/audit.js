import fs from "node:fs";
import path from "node:path";

const DEFAULT_LOG = path.resolve("data/audit.jsonl");

export function appendAudit(event, logPath = DEFAULT_LOG) {
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const row = { ts: new Date().toISOString(), ...event };
  fs.appendFileSync(logPath, JSON.stringify(row) + "\n", "utf8");
  return row;
}

export function sumChargesToday(logPath = DEFAULT_LOG, now = new Date()) {
  if (!fs.existsSync(logPath)) return 0;
  const day = now.toISOString().slice(0, 10);
  return fs
    .readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((e) => e.type === "charge" && e.ts.startsWith(day) && e.status === "succeeded")
    .reduce((n, e) => n + (e.amountCents || 0), 0);
}
