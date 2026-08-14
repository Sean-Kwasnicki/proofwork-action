import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { buildGitContext } from "../gitContext.js";
const FINGERPRINT_PATH = ".proofwork/deleted-fingerprints.json";
/**
 * Proprietary normalization — raises cost of naive reimplementation.
 * Keep details out of public posts (see docs/MOAT.md).
 */
function normalizeLine(line) {
    let t = line.replace(/\s+/g, " ").trim();
    // Drop trailing punctuation noise that agents often reflow
    t = t.replace(/[;,]+\s*$/g, "");
    // Collapse trivial string-literal differences that aren't semantic identity
    t = t.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, "$1…$1");
    return t;
}
/** Salted content hash — store format is Proofwork-specific (v3). */
function hashContent(line) {
    return createHash("sha256")
        .update("pw.integrity.v3\0")
        .update(normalizeLine(line))
        .digest("hex");
}
export function isNoiseLine(line) {
    const t = normalizeLine(line);
    if (!t)
        return true;
    if (t.length < 12)
        return true;
    if (/^[{}[\]();,.:]+$/.test(t))
        return true;
    if (/^\/\//.test(t) || /^\/\*/.test(t) || /^\*/.test(t) || /^\*\//.test(t))
        return true;
    if (/^#/.test(t) && t.length < 40)
        return true;
    if (/^import\s+/.test(t))
        return true;
    if (/^export\s+(type|interface|\{)/.test(t))
        return true;
    if (/^from\s+['"]/.test(t))
        return true;
    if (/^console\.(log|debug|info)\(/.test(t))
        return true;
    if (!/[A-Za-z_][A-Za-z0-9_]{2,}/.test(t))
        return true;
    return false;
}
/**
 * Paths that are not product zombie-code signal.
 * Docs/marketing HTML churn must not poison the fingerprint store — that blocked
 * engine self-certify and taught buyers the wrong lesson.
 */
export function isIgnoredPath(file) {
    const f = file.replace(/\\/g, "/");
    const base = f.includes("/") ? f.slice(f.lastIndexOf("/") + 1) : f;
    const ext = base.includes(".") ? base.slice(base.lastIndexOf(".")).toLowerCase() : "";
    return (f.startsWith(".proofwork/") ||
        f.includes("/.proofwork/") ||
        f.startsWith("node_modules/") ||
        f.includes("/node_modules/") ||
        f.startsWith(".agentsaver/") ||
        f.startsWith("docs/") ||
        f.startsWith("site/") ||
        f.startsWith(".cursor/") ||
        base === "MEMORY.md" ||
        base === "NEXT_AGENT_PROMPT.md" ||
        base === "SESSION_NOTES.md" ||
        base === "TASKS.md" ||
        // Prose / marketing / lockfiles — zombie check targets application source
        ext === ".md" ||
        ext === ".html" ||
        ext === ".css" ||
        base === "package-lock.json" ||
        base === "evidence.json");
}
function emptyStore() {
    return {
        version: 3,
        scheme: "pw.integrity.v3",
        updated_at: new Date().toISOString(),
        hashes: [],
        samples: {},
    };
}
function loadStore(root) {
    const p = path.join(root, FINGERPRINT_PATH);
    if (!fs.existsSync(p))
        return emptyStore();
    try {
        const raw = JSON.parse(fs.readFileSync(p, "utf8"));
        // Prior schemes used different hashes — start clean rather than false-match.
        if (raw.version !== 3 || raw.scheme !== "pw.integrity.v3")
            return emptyStore();
        const samples = raw.samples ?? {};
        const hashes = (raw.hashes ?? []).filter((h) => {
            const sample = samples[h];
            if (!sample)
                return true;
            const file = sample.split(":")[0]?.trim() ?? "";
            return file ? !isIgnoredPath(file) : true;
        });
        const origins = raw.origins ?? {};
        const nextSamples = {};
        const nextOrigins = {};
        for (const h of hashes) {
            if (samples[h])
                nextSamples[h] = samples[h];
            if (origins[h])
                nextOrigins[h] = origins[h];
        }
        return {
            version: 3,
            scheme: "pw.integrity.v3",
            updated_at: raw.updated_at ?? new Date().toISOString(),
            hashes,
            samples: nextSamples,
            origins: nextOrigins,
        };
    }
    catch {
        return emptyStore();
    }
}
const MAX_FINGERPRINTS = 5_000;
/**
 * Grading must be able to leave no trace.
 *
 * This check remembers deleted code so it can notice the same code returning
 * later, and that memory has to live somewhere — historically `.proofwork/`
 * inside the repository being graded.
 *
 * That is wrong for a tool people point at code they do not own. Reading someone
 * else's repository and writing into it is a side effect nobody asked for: it
 * dirties their working tree, shows up in their `git status`, and can end up
 * committed by whoever runs `git add -A` next. It happened here — a scoreboard
 * run over a corpus of thirteen repositories modified all thirteen.
 *
 * `PROOFWORK_READONLY=1` makes every persistence step a no-op. The check still
 * runs and still reports; it simply forgets afterwards, which is the correct
 * trade when the alternative is mutating a stranger's repository.
 */
export const isReadOnly = () => process.env.PROOFWORK_READONLY === "1";
function saveStore(root, store) {
    if (isReadOnly())
        return;
    const p = path.join(root, FINGERPRINT_PATH);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    // Cap store for latency + disk — keep newest hashes
    if (store.hashes.length > MAX_FINGERPRINTS) {
        const keep = store.hashes.slice(-MAX_FINGERPRINTS);
        store.hashes = keep;
        const nextSamples = {};
        const nextOrigins = {};
        for (const h of keep) {
            if (store.samples[h])
                nextSamples[h] = store.samples[h];
            if (store.origins?.[h])
                nextOrigins[h] = store.origins[h];
        }
        store.samples = nextSamples;
        store.origins = nextOrigins;
    }
    store.updated_at = new Date().toISOString();
    store.version = 3;
    store.scheme = "pw.integrity.v3";
    fs.writeFileSync(p, `${JSON.stringify(store)}\n`, "utf8");
}
/** Parse unified diff; collect deleted and added content lines with file paths. */
export function parseDiffLines(diff) {
    const deleted = [];
    const added = [];
    let seq = 0;
    // Both sides required: whole-file deletes use `+++ /dev/null` (no `+++ b/`).
    let aFile = "";
    let bFile = "";
    for (const raw of diff.split(/\r?\n/)) {
        seq += 1;
        if (raw.startsWith("--- a/")) {
            aFile = raw.slice(6);
            continue;
        }
        if (raw.startsWith("--- /dev/null")) {
            aFile = "";
            continue;
        }
        if (raw.startsWith("+++ b/")) {
            bFile = raw.slice(6);
            continue;
        }
        if (raw.startsWith("+++ /dev/null")) {
            bFile = "";
            continue;
        }
        if (raw.startsWith("diff ") || raw.startsWith("index ") || raw.startsWith("@@"))
            continue;
        if (raw.startsWith("+") && !raw.startsWith("+++")) {
            if (bFile)
                added.push({ file: bFile, line: raw.slice(1), seq });
        }
        else if (raw.startsWith("-") && !raw.startsWith("---")) {
            if (aFile)
                deleted.push({ file: aFile, line: raw.slice(1) });
        }
    }
    return { deleted, added };
}
export function runReintroductionChecks(root, git) {
    const store = loadStore(root);
    const prior = new Set(store.hashes);
    const ctx = git ?? buildGitContext(root);
    const diff = ctx.unifiedDiff;
    if (!diff.trim()) {
        return [
            {
                id: "integrity.reintroduction",
                title: "Deleted-code reintroduction",
                status: "pass",
                detail: "No diff to scan — store retained for future checks",
                evidence: { known_fingerprints: prior.size },
            },
        ];
    }
    const { deleted, added } = parseDiffLines(diff);
    let newFingerprints = 0;
    const thisDiffDeletes = new Set();
    for (const d of deleted) {
        if (isIgnoredPath(d.file) || isNoiseLine(d.line))
            continue;
        const h = hashContent(d.line);
        thisDiffDeletes.add(h);
        if (!prior.has(h) && !store.hashes.includes(h)) {
            store.hashes.push(h);
            store.samples[h] = `${d.file}: ${normalizeLine(d.line).slice(0, 160)}`;
            store.origins = store.origins ?? {};
            store.origins[h] = d.file;
            newFingerprints += 1;
        }
    }
    saveStore(root, store);
    /**
     * A zombie comes back where it was buried.
     *
     * Matching on content alone made this check fire on ordinary work: a new test
     * file was reported as resurrecting deleted code because it contained
     * `fs.writeFileSync(` — a line once removed from a *different* test, and present
     * in nearly every file that writes anything. "Previously deleted code
     * reappeared" was simply untrue, and it sends the reader hunting through history
     * for a deletion that never happened.
     *
     * Requiring the same file is the right discriminator, and it is stronger than
     * the obvious alternatives. Demanding a multi-line block would have been easy
     * and wrong — it silently stops catching the single-line zombie, which is the
     * canonical case: one guard, one threshold, one early return that somebody
     * removed deliberately and an agent restored. This project's own selftest
     * caught that regression immediately.
     *
     * Deletion and reappearance in the same file is what "this was removed on
     * purpose and came back" actually means. The same text written in a different
     * file is somebody using a common idiom, which is not a claim worth making.
     *
     * The cost is a real gap, stated rather than hidden: code deleted from one file
     * and resurrected in another is not caught. That is a weaker claim to begin with
     * — moved code is refactoring far more often than it is reversion — and the
     * checks that judge behaviour do not care which file it lives in.
     */
    const confirmed = [];
    for (const a of added) {
        if (isIgnoredPath(a.file) || isNoiseLine(a.line))
            continue;
        const h = hashContent(a.line);
        if (!prior.has(h))
            continue;
        if (thisDiffDeletes.has(h))
            continue;
        // Where it was deleted from. Absent for entries written by an older store,
        // which are treated as matching so an upgrade never loses a real detection.
        const origin = store.origins?.[h];
        if (origin && origin !== a.file)
            continue;
        confirmed.push({
            file: a.file,
            sample: store.samples[h] ?? normalizeLine(a.line).slice(0, 160),
        });
    }
    const uniq = new Map();
    for (const h of confirmed)
        uniq.set(`${h.file}|${h.sample}`, h);
    const list = [...uniq.values()].slice(0, 10);
    if (list.length > 0) {
        return [
            {
                id: "integrity.reintroduction",
                title: "Deleted-code reintroduction",
                status: "fail",
                detail: `Previously deleted code reappeared (${list.length} hit(s))`,
                evidence: {
                    hits: list,
                    new_fingerprints_recorded: newFingerprints,
                    prior_fingerprints: prior.size,
                    total_fingerprints: store.hashes.length,
                },
            },
        ];
    }
    return [
        {
            id: "integrity.reintroduction",
            title: "Deleted-code reintroduction",
            status: "pass",
            detail: `No reintroduction vs prior store (recorded ${newFingerprints} new deletion fingerprint(s); prior=${prior.size})`,
            evidence: {
                new_fingerprints_recorded: newFingerprints,
                prior_fingerprints: prior.size,
                total_fingerprints: store.hashes.length,
            },
        },
    ];
}
