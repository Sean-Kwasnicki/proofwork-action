import crypto from "node:crypto";
import { tryExec } from "./util/exec.js";
/**
 * Proof binding — ties a proof to the exact repository state it describes.
 *
 * ## Why signing alone is not enough
 *
 * The attestation chain HMACs entries with a secret stored under `.proofwork/`.
 * That detects edits by a third party, but an agent working in the repo can read
 * the secret, and — more simply — can just run `proofwork` again after making a
 * change and get a freshly valid signature. Any scheme where the agent can invoke
 * the signer cannot be made forgery-proof by adding more signing.
 *
 * The property that *does* hold is narrower and more useful: a proof is valid for
 * one tree state and no other. That defeats the realistic attacks:
 *
 *   - **Replay** — run the gate on clean code, then apply the bad change and
 *     present the old passing proof. The tree digest no longer matches.
 *   - **Transplant** — copy a passing proof from another branch, repo, or commit.
 *     The commit and digest disagree with the tree being verified.
 *   - **Post-hoc edit** — mutate `.proofwork/latest.json` to flip `ok` to true.
 *     The recorded digest still describes the real tree, and `ok` is recomputed
 *     from the checks rather than trusted, so the edit is visible.
 *
 * ## What it explicitly does NOT stop
 *
 * An agent that fixes nothing but re-runs the gate on its own modified tree gets a
 * legitimately new proof — for a tree that still fails. That is correct behaviour:
 * binding is about provenance, not about the verdict. The verdict is the checks'
 * job. Stating this plainly so nobody mistakes binding for tamper-proofing.
 *
 * ## Consumer rule
 *
 * CI must treat a proof file as a *claim*, never as evidence. Either re-run the
 * gate, or call `verifyTreeBinding` against the tree in front of it and reject a
 * mismatch. A proof read and trusted without either step is worth nothing.
 */
/** Digest algorithm identifier, recorded so the scheme can change without ambiguity. */
const BINDING_ALGO = "sha256/git-ls-files+worktree-diff/v1";
/** Cap on the unstaged diff we hash. Beyond this the digest records the overflow. */
const MAX_DIFF_BYTES = 8 * 1024 * 1024;
const GIT_TIMEOUT_MS = 10_000;
/**
 * Resolve the base ref used to pin grader policy, and report how trustworthy the
 * source is.
 *
 * `PROOFWORK_BASE_REF` is an ordinary environment variable, so anything that can
 * run a shell — very much including a coding agent — can set it. Pointing it at
 * the agent's own branch makes "base-pinned policy" read the policy the agent just
 * edited, which silently converts the strongest defence into no defence at all.
 *
 * Under a recognised CI provider the platform sets the base ref itself, so we take
 * that value and *ignore* the overridable one. Outside CI we still accept the local
 * variable — it is genuinely useful for development — but mark it `local-env` so
 * the weaker provenance travels with the proof instead of being invisible.
 */
export function resolveBaseRef(env = process.env) {
    // GITHUB_ACTIONS is set by the runner, not by the workflow author.
    const inTrustedCi = env.GITHUB_ACTIONS === "true";
    if (inTrustedCi) {
        const ref = env.GITHUB_BASE_REF?.trim();
        // On a push build there is no base ref; that is "none", not a fallback to the
        // agent-settable variable. Falling back here would reopen the whole hole.
        return ref ? { ref, source: "ci" } : { ref: null, source: "none" };
    }
    const local = (env.PROOFWORK_BASE_REF || env.GITHUB_BASE_REF)?.trim();
    return local ? { ref: local, source: "local-env" } : { ref: null, source: "none" };
}
/** True when policy pinned to this source can be trusted to be outside agent control. */
export function isTrustedBaseSource(source) {
    return source === "ci";
}
function sha256(input) {
    return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}
/**
 * Compute the binding for the tree at `root`.
 *
 * `git ls-files -s` emits mode, blob hash, stage and path per tracked file — git's
 * own content hashes, so we get a deterministic digest without reading file bodies.
 * That covers everything committed or staged. Unstaged edits do not change those
 * blob hashes, so the worktree diff is hashed alongside; together they pin the
 * exact bytes a reviewer would see.
 */
export function computeTreeBinding(root, env = process.env) {
    const { ref: base_ref, source: base_ref_source } = resolveBaseRef(env);
    const head = tryExec("git", ["rev-parse", "HEAD"], root, GIT_TIMEOUT_MS);
    const commit = head.ok && head.out.trim() ? head.out.trim() : null;
    const listed = tryExec("git", ["ls-files", "-s"], root, GIT_TIMEOUT_MS);
    if (!listed.ok) {
        // Outside a git repo there is no tree to bind to. Say so explicitly rather
        // than emitting a digest of nothing that would compare equal to another
        // non-repo — an empty digest that matches everything is worse than none.
        return {
            algo: BINDING_ALGO,
            commit,
            tree_digest: "unbound:not-a-git-repo",
            file_count: 0,
            dirty: false,
            base_ref,
            base_ref_source,
        };
    }
    const index = listed.out.split(/\r?\n/).filter(Boolean).sort();
    const diff = tryExec("git", ["diff", "--no-ext-diff", "--no-color"], root, GIT_TIMEOUT_MS);
    const rawDiff = diff.ok ? diff.out : "";
    // Hash a truncated diff rather than skipping it: an enormous diff must still
    // change the digest, and the marker keeps the two cases distinguishable.
    const diffPart = rawDiff.length > MAX_DIFF_BYTES
        ? `truncated:${rawDiff.length}:${sha256(rawDiff.slice(0, MAX_DIFF_BYTES))}`
        : rawDiff;
    return {
        algo: BINDING_ALGO,
        commit,
        tree_digest: sha256(`${commit ?? "no-head"}\n${index.join("\n")}\n--diff--\n${diffPart}`),
        file_count: index.length,
        dirty: rawDiff.trim().length > 0,
        base_ref,
        base_ref_source,
    };
}
/**
 * Recompute the binding for the current tree and compare it to the one recorded in
 * a proof. This is what CI should call before believing any proof it did not
 * produce itself.
 */
export function verifyTreeBinding(root, recorded, env = process.env) {
    if (!recorded) {
        return {
            ok: false,
            reasons: [
                "Proof carries no tree binding — it cannot be tied to this checkout. " +
                    "Re-run proofwork instead of trusting it.",
            ],
        };
    }
    if (recorded.algo !== BINDING_ALGO) {
        return {
            ok: false,
            reasons: [`Unknown binding algorithm "${recorded.algo}" — refusing to compare.`],
        };
    }
    const current = computeTreeBinding(root, env);
    const reasons = [];
    if (current.tree_digest.startsWith("unbound:")) {
        reasons.push("Current directory is not a git repository — nothing to bind against.");
    }
    if (recorded.commit !== current.commit) {
        reasons.push(`Proof was produced at commit ${recorded.commit ?? "(none)"}, tree is at ${current.commit ?? "(none)"}.`);
    }
    if (recorded.tree_digest !== current.tree_digest) {
        reasons.push("Tree digest mismatch — files changed after this proof was produced.");
    }
    return {
        ok: reasons.length === 0,
        reasons,
        expected: recorded.tree_digest,
        actual: current.tree_digest,
    };
}
