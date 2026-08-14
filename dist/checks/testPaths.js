import { existsSync, readdirSync } from "node:fs";
/**
 * One definition of "this is a test file", shared by every check that needs it.
 *
 * ## Why this module exists
 *
 * `fakeGreen` and `workmanship` each carried their own path matcher, and the two
 * disagreed. `workmanship` recognised `__tests__/` but not `tests/`; `fakeGreen`
 * recognised `tests/` but neither recognised `e2e/`. A red-team engagement put
 * hollow tests in `e2e/` and both checks looked straight past them — the files
 * were never classified as tests, so the code that inspects tests never ran.
 *
 * The failure was made worse by how it was tested. This project's own adversary
 * suite asserted that `findHollowTests("e2e/checkout.ts", …)` returns a finding,
 * and it does — because that test calls the detector *directly*. The real code
 * path asks the routing question first, and the routing was what was broken. A
 * unit test that bypasses the dispatch it depends on can pass while the feature
 * is entirely non-functional, which is precisely the class of defect this
 * product exists to catch. Finding it in our own suite is not ironic; it is the
 * expected outcome of taking the idea seriously.
 *
 * Two checks with two definitions will drift again. One definition cannot.
 */
/**
 * Directory names that hold tests across the ecosystems we support.
 *
 * Deliberately broad. A missed convention means a whole directory of tests goes
 * unexamined, which is silent; a wrongly-included directory means source files
 * are scanned for hollow tests and find none, which is harmless. The asymmetry
 * points one way.
 */
const TEST_DIRS = [
    "__tests__",
    "__test__",
    "test",
    "tests",
    "spec",
    "specs",
    "e2e",
    "integration",
    "acceptance",
    "cypress",
    "playwright",
    "testdata",
    "__mocks__",
    // Sample and fixture directories. `testdata` was already here and these are the
    // same idea under the names the rest of the world uses. Their absence was not
    // theoretical: an honest security agent kept attack samples in
    // `fixtures/attacks/*.sample.js`, and the quoted `stripe.charges.create(…)`
    // inside them was read as the agent's own money-moving code.
    "fixtures",
    "fixture",
    "samples",
];
const TEST_DIR_RE = new RegExp(`(?:^|/)(?:${TEST_DIRS.join("|")})/`, "i");
/**
 * Filename conventions.
 *
 * `.tests.` with an s is included: it is a common typo-turned-convention, and it
 * was one of the paths a red-team agent used to hide hollow tests.
 */
const TEST_FILE_RE = /\.(?:test|tests|spec|specs|sample|samples|fixture|fixtures)\.[cm]?[jt]sx?$|_test\.(?:py|go|rb)$|(?:^|\/)test_[^/]+\.py$|Test\.java$|_spec\.rb$/i;
/** Is this path a test file, by name or by the directory it sits in? */
export function isTestPath(p) {
    const norm = p.replace(/\\/g, "/");
    return TEST_FILE_RE.test(norm) || TEST_DIR_RE.test(norm);
}
/** Source we would expect to be covered by tests. */
export function isSourcePath(p) {
    const norm = p.replace(/\\/g, "/");
    return (/\.[cm]?[jt]sx?$|\.py$|\.rb$|\.go$|\.java$|\.cs$/i.test(norm) &&
        !isTestPath(norm) &&
        !/\.d\.ts$/i.test(norm) &&
        !/\.config\.[cm]?[jt]s$/i.test(norm));
}
/** Directories never worth walking, shared so the walkers cannot diverge either. */
export const WALK_SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", "out", "coverage",
    "vendor", ".venv", "venv", "__pycache__", ".proofwork", ".cache",
]);
/**
 * Should the walk descend into this directory?
 *
 * One helper so every check answers the question the same way. The two conditions
 * are the same idea seen from either side: a directory that *is* another
 * repository, and a directory that *holds* other repositories. Neither is the
 * project being graded, and code found in either belongs to somebody else.
 */
export function isForeignTree(dirPath) {
    const base = dirPath.replace(/[\\/]$/, "");
    if (existsSync(`${base}/.git`))
        return true;
    return holdsForeignRepos(base, readDirNames, existsSync);
}
/**
 * Does this repository-relative path live inside somebody else's tree?
 *
 * The walkers refuse to descend into a foreign tree, which covers the checks that
 * scan the filesystem. It does not cover the ones that read `changedFiles`: a
 * corpus checked out inside the working directory shows up in `git status` like
 * anything else, so diff-mode checks were still reading it. Same defect, other
 * entrance.
 *
 * Walks the path upward rather than testing the leaf, because the marker sits on
 * an ancestor — `red-team/build-attacks.mjs` is foreign by virtue of `red-team/`,
 * and nothing about the file itself says so.
 */
export function isUnderForeignTree(root, relPath) {
    const parts = relPath.replace(/\\/g, "/").split("/");
    parts.pop(); // the file itself
    let cursor = root.replace(/[\\/]$/, "");
    for (const part of parts) {
        cursor = `${cursor}/${part}`;
        if (isForeignTree(cursor))
            return true;
    }
    return false;
}
/** Immediate subdirectory names, or empty when the path cannot be read. */
function readDirNames(p) {
    return readdirSync(p, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => e.name);
}
/**
 * A directory that *holds* other repositories is a corpus, not application code.
 *
 * Excluding nested repositories closed most of the problem and left a seam. A
 * corpus directory contains the sub-repositories plus the tooling that generated
 * them — build scripts, manifests, notes — and those top-level files belong to no
 * nested repository, so they were still read as this project's own source. This
 * repository was reported as failing transparency and automated-decision duties
 * on the strength of a script whose job is to *write* unlawful agents for the
 * gate to catch.
 *
 * Judging a directory by what it contains rather than by its name keeps the rule
 * general. `examples/`, `vendor/`, a folder of cloned reference projects, and a
 * red-team corpus are all the same shape: a place where other people's
 * repositories live. None of them is the project being graded.
 *
 * The check is deliberately shallow — immediate children only. A deep scan on
 * every directory during a walk is expensive, and the shape being detected always
 * appears one level down.
 *
 * The filesystem calls are injected so this stays testable without a real tree.
 */
export function holdsForeignRepos(dirPath, readdir, exists) {
    let children;
    try {
        children = readdir(dirPath);
    }
    catch {
        return false;
    }
    const base = dirPath.replace(/[\\/]$/, "");
    return children.some((c) => exists(`${base}/${c}/.git`));
}
