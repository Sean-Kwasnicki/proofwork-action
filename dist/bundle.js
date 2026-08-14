import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { WALK_SKIP_DIRS } from "./checks/testPaths.js";
/**
 * Bundle intake — grading an agent that is not a git checkout.
 *
 * ## Why this exists
 *
 * Everything upstream assumes a git repository, because a verdict is bound to a
 * commit and a commit is what makes a certificate mean one exact state. That
 * assumption is fine for a repository we are asked to gate in CI and useless for
 * the case this phase is about: an agent already running in production, whose
 * owner can export a directory or a zip and cannot hand over a clone.
 *
 * Refusing those is refusing most of the market. Pretending they have a commit is
 * worse — it would put a number on a certificate that looks like a git SHA, means
 * something else entirely, and cannot be checked out by the person reading it.
 *
 * ## What replaces the commit
 *
 * A content digest over the bundle, recorded as `bundle_sha256:<hex>` and labelled
 * as such everywhere it surfaces. It is genuinely weaker than a commit and the
 * difference is stated rather than papered over:
 *
 *   - A commit is a name in a history someone else can fetch and inspect. A bundle
 *     hash names bytes we were handed, with no history and no independent copy.
 *   - Two people with the same commit provably have the same code. Two people with
 *     the same bundle hash have the same bytes *if* they hash them the same way,
 *     which is why the algorithm is recorded in the binding.
 *
 * What it does do is the thing binding is for: it pins the verdict to one exact
 * state, so a proof cannot be replayed against different code.
 *
 * ## The digest
 *
 * Files are hashed by relative path and content, sorted, then folded into one
 * digest. Sorting matters — filesystem enumeration order varies by platform, and a
 * digest that changed between Windows and Linux for identical bytes would make
 * every cross-platform verification fail for no reason.
 */
export const BUNDLE_ALGO = "sha256/bundle-content/v1";
/** Files past this size are recorded by size rather than read. */
const MAX_FILE_BYTES = 2 * 1024 * 1024;
/** Refuse absurd inputs rather than hashing for ten minutes. */
const MAX_FILES = 20_000;
/**
 * Resolve `--bundle <path>` to a directory of files.
 *
 * A directory is used in place. An archive is expanded into a temp directory —
 * never next to the archive, which would write into a location the user did not
 * ask us to modify.
 */
export function openBundle(input) {
    const abs = path.resolve(input);
    if (!fs.existsSync(abs)) {
        throw new Error(`No such bundle: ${abs}`);
    }
    const stat = fs.statSync(abs);
    if (stat.isDirectory()) {
        return { root: abs, tempDir: null, label: path.basename(abs) };
    }
    if (!/\.(zip|tgz|tar\.gz|tar)$/i.test(abs)) {
        throw new Error(`Not a directory or a recognised archive: ${abs}\n` +
            `Supported: a directory, or .zip / .tar / .tar.gz / .tgz`);
    }
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "proofwork-bundle-"));
    extractArchive(abs, tempDir);
    return { root: descendSingleRoot(tempDir), tempDir, label: path.basename(abs) };
}
/**
 * Which `tar` is on this machine.
 *
 * Cached because it costs a process spawn and cannot change mid-run.
 */
let tarFlavour = null;
function detectTar() {
    if (tarFlavour)
        return tarFlavour;
    try {
        const out = execFileSync("tar", ["--version"], { stdio: "pipe", timeout: 10_000 }).toString();
        tarFlavour = /GNU tar/i.test(out) ? "gnu" : "other";
    }
    catch {
        tarFlavour = "missing";
    }
    return tarFlavour;
}
/** Test seam — lets the suite assert both flavours without two machines. */
export function resetTarDetection() {
    tarFlavour = null;
}
/**
 * Arguments for a `tar` invocation, corrected for the tar that is actually installed.
 *
 * ## The bug this exists to fix
 *
 * GNU tar reads an argument containing a colon as `host:path` and tries to reach a
 * remote machine. On Windows every absolute path starts with a drive letter, so
 * `tar -xf C:\Users\...\agent.zip` fails with:
 *
 *     tar: Cannot connect to C: resolve failed
 *
 * Windows ships bsdtar at `C:\Windows\System32\tar.exe`, which handles drive
 * letters correctly — so whether bundle intake worked depended entirely on which
 * `tar` came first in PATH. Anyone with Git for Windows installed, which is
 * essentially every developer on the platform, gets GNU tar first and would have
 * had `--bundle agent.zip` fail on their first attempt at the feature built
 * specifically for people who cannot hand over a clone.
 *
 * `--force-local` tells GNU tar the name is a local file. bsdtar does not
 * recognise the flag and errors on it, so it is added only when GNU tar is what we
 * are talking to.
 */
export function tarArgs(args) {
    return detectTar() === "gnu" ? ["--force-local", ...args] : args;
}
/**
 * Expand an archive using tools already on the machine.
 *
 * `tar` handles zip on Windows 10+ and everywhere else worth supporting, and using
 * it avoids taking an unzip dependency into a project that has none. If it is
 * missing, that is said plainly rather than surfaced as a spawn error.
 */
function extractArchive(archive, into) {
    if (detectTar() === "missing") {
        throw new Error(`Could not expand ${path.basename(archive)}: no \`tar\` on this machine.\n` +
            `tar ships with Windows 10+, macOS, and Linux. Expand the archive yourself\n` +
            `and pass the directory instead.`);
    }
    try {
        execFileSync("tar", tarArgs(["-xf", archive, "-C", into]), { stdio: "pipe", timeout: 120_000 });
    }
    catch (e) {
        const stderr = e && typeof e === "object" && "stderr" in e ? String(e.stderr).trim() : "";
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`Could not expand ${path.basename(archive)}: ${stderr || msg}\n` +
            `Proofwork shells out to \`tar\`, which ships with Windows 10+, macOS, and Linux.\n` +
            `If it is unavailable, expand the archive yourself and pass the directory instead.`);
    }
}
/**
 * Follow a single wrapper directory.
 *
 * Archives are usually made from a parent folder, so expanding gives
 * `tmp/my-agent/…` rather than `tmp/…`. Grading the wrapper finds one directory
 * and no source, and reports an empty repository — technically true and useless.
 */
function descendSingleRoot(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true }).filter((e) => !e.name.startsWith("."));
    if (entries.length === 1 && entries[0].isDirectory()) {
        return path.join(dir, entries[0].name);
    }
    return dir;
}
/** Remove anything we unpacked. Safe to call when nothing was. */
export function closeBundle(src) {
    if (!src.tempDir)
        return;
    try {
        fs.rmSync(src.tempDir, { recursive: true, force: true });
    }
    catch {
        // A leftover temp directory is not worth failing a completed run over.
    }
}
/**
 * Content digest over every file in the bundle.
 *
 * Skipped directories match the ones the walkers already ignore, so a bundle that
 * happens to ship `node_modules` does not produce a digest dominated by
 * dependencies — and, more importantly, does not produce a *different* digest for
 * the same agent depending on whether the exporter ran an install first.
 */
export function digestBundle(root) {
    const parts = [];
    let oversize = 0;
    const walk = (dir) => {
        if (parts.length > MAX_FILES)
            return;
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
            const abs = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (!WALK_SKIP_DIRS.has(e.name))
                    walk(abs);
                continue;
            }
            const rel = path.relative(root, abs).replace(/\\/g, "/");
            try {
                const size = fs.statSync(abs).size;
                if (size > MAX_FILE_BYTES) {
                    // Recorded by size rather than content. A large binary still changes the
                    // digest if its size changes, and reading it would dominate the run.
                    oversize += 1;
                    parts.push(`${rel}\0oversize:${size}`);
                    continue;
                }
                const hash = crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
                parts.push(`${rel}\0${hash}`);
            }
            catch {
                // Unreadable file. Recorded as such so its presence still affects the
                // digest — silently dropping it would let an unreadable file hide a change.
                parts.push(`${rel}\0unreadable`);
            }
        }
    };
    walk(root);
    // Sorted, because readdir order varies by platform and a digest that differed
    // between Windows and Linux for identical bytes would fail every cross-platform
    // verification for no reason.
    parts.sort();
    return {
        digest: crypto.createHash("sha256").update(parts.join("\n")).digest("hex"),
        file_count: parts.length,
        oversize,
    };
}
/**
 * A binding for a bundle, shaped like a tree binding so everything downstream —
 * proofs, credentials, the registry — keeps working unchanged.
 *
 * `commit` is null, deliberately and always. Filling it with the bundle hash would
 * make a certificate display something that looks like a git SHA and is not one,
 * and the person reading it would try to check it out. The binding type is carried
 * in `algo` and surfaced by every renderer.
 */
export function computeBundleBinding(root) {
    const d = digestBundle(root);
    return {
        algo: BUNDLE_ALGO,
        commit: null,
        tree_digest: `bundle_sha256:${d.digest}`,
        file_count: d.file_count,
        // A bundle has no index to be dirty against. Reporting `true` would imply
        // uncommitted work, which is not a coherent statement about a zip file.
        dirty: false,
        base_ref: null,
        base_ref_source: "none",
        bundle_sha256: d.digest,
    };
}
export const BUNDLE_DIGEST_PREFIX = "bundle_sha256:";
/**
 * Is this a bundle rather than a commit?
 *
 * Checks the digest as well as `algo`, because a `RegistryEntry` has no `algo` —
 * the record keeps `commit`, `tree_digest`, and nothing about the algorithm. The
 * digest prefix is the discriminator that survives into the signed record, so it
 * is the one every downstream reader can rely on.
 */
export function isBundleBinding(b) {
    if (b?.algo === BUNDLE_ALGO)
        return true;
    return typeof b?.tree_digest === "string" && b.tree_digest.startsWith(BUNDLE_DIGEST_PREFIX);
}
/**
 * How a binding must be described wherever a commit would otherwise be printed.
 *
 * One function so the CLI, the certificate, the badge, the registry record, and
 * the verify page cannot drift into describing the same binding differently.
 *
 * That drift is not hypothetical — it shipped. This function existed, was tested,
 * and was called by nothing. Every live surface went on printing "commit unbound"
 * for bundle-bound proofs while the signed record correctly carried
 * `bundle_sha256:…`. The bytes were right and the words were wrong, which is
 * precisely the failure this product sells itself on catching, and a reviewer
 * found it in our own output.
 */
export function describeBinding(b) {
    if (isBundleBinding(b)) {
        const hex = (b?.tree_digest ?? "").replace(new RegExp(`^${BUNDLE_DIGEST_PREFIX}`), "");
        const short = hex.slice(0, 16) || "unknown";
        return {
            kind: "bundle",
            label: "Bundle SHA-256",
            value: hex || "unknown",
            short,
            phrase: `the bundle ${short}`,
        };
    }
    if (b?.commit) {
        return {
            kind: "commit",
            label: "Commit",
            value: b.commit,
            short: b.commit.slice(0, 8),
            phrase: `commit ${b.commit.slice(0, 8)}`,
        };
    }
    return {
        kind: "unbound",
        label: "Binding",
        value: "unbound",
        short: "unbound",
        // Never "commit unbound" — there is no commit, and naming one implies a git
        // history that does not exist for this proof.
        phrase: "the state examined (no commit or bundle digest recorded)",
    };
}
