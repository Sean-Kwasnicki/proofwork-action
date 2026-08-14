import { computeTreeBinding } from "./binding.js";
import { computeBundleBinding, describeBinding, isBundleBinding } from "./bundle.js";
/**
 * Compare a record against the working tree at `root`.
 *
 * `unknown` is a first-class answer and used whenever the comparison would be
 * apples to oranges — a commit-bound record checked outside a git repository, or
 * a bundle-bound record checked against one. Guessing in either direction would
 * be worse than the silence this replaces: reporting "stale" for a record that
 * simply describes a different project is a false alarm, and reporting "current"
 * on no evidence is the failure this whole product exists to prevent.
 */
export function assessFreshness(entry, root) {
    const bound = describeBinding(entry);
    if (isBundleBinding(entry)) {
        const current = computeBundleBinding(root);
        if (current.tree_digest === entry.tree_digest) {
            return {
                state: "current",
                boundTo: bound.label,
                note: `Describes the bundle in front of you — the content digest still matches.`,
            };
        }
        return {
            state: "stale",
            boundTo: bound.label,
            note: `Describes a different bundle than the one here. This record is still valid; it ` +
                `attests to the content it was issued for, and that content has changed. Re-check to ` +
                `cover what you have now.`,
            expected: entry.tree_digest ?? "",
            actual: current.tree_digest,
        };
    }
    // Commit-bound from here. A record with neither a commit nor a bundle digest
    // was issued unbound and cannot be compared to anything.
    if (!entry.commit) {
        return {
            state: "unknown",
            boundTo: bound.label,
            note: "Carries no commit or bundle digest, so it cannot be matched to any particular state.",
        };
    }
    const current = computeTreeBinding(root);
    if (!current.commit) {
        return {
            state: "unknown",
            boundTo: bound.label,
            note: `Bound to commit ${entry.commit.slice(0, 8)}, but this directory is not a git ` +
                `repository, so there is nothing to compare it against.`,
        };
    }
    if (current.commit !== entry.commit) {
        return {
            state: "stale",
            boundTo: bound.label,
            note: `Bound to commit ${entry.commit.slice(0, 8)}; this checkout is at ` +
                `${current.commit.slice(0, 8)}. The record is still valid — it attests to the commit it ` +
                `names — but that is not the code here. Re-check to cover the current commit.`,
            expected: entry.commit,
            actual: current.commit,
        };
    }
    // Same commit, but the working tree may carry uncommitted edits. The record was
    // issued for an exact tree digest, and a dirty tree is not that tree.
    if (entry.tree_digest && entry.tree_digest !== current.tree_digest) {
        return {
            state: "stale",
            boundTo: bound.label,
            note: `On the commit this record names, but the working tree has changed since it was ` +
                `issued. The verdict describes the tree as it was, not as it is.`,
            expected: entry.tree_digest,
            actual: current.tree_digest,
        };
    }
    return {
        state: "current",
        boundTo: bound.label,
        note: `Describes the code in front of you — commit and working tree both match.`,
    };
}
/** One-word marker for a table or a list. */
export function freshnessLabel(state) {
    return state === "current" ? "CURRENT" : state === "stale" ? "STALE" : "UNKNOWN";
}
/**
 * The sentence every surface should print about what a certificate covers.
 *
 * Kept in one place so the CLI, the vault, the certificate, and the docs cannot
 * drift into describing the scope differently — the same reason
 * `describeBinding` exists, and the same failure it was written after.
 */
export function scopeSentence(entry) {
    const bound = describeBinding(entry);
    return bound.kind === "bundle"
        ? `This record attests to one bundle digest (${bound.short}). It makes no claim about any other version of this agent.`
        : bound.kind === "commit"
            ? `This record attests to one commit (${bound.short}). It makes no claim about any later commit.`
            : `This record carries no binding, so it attests to no particular state.`;
}
