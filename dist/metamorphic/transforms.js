/**
 * Semantics-preserving and fault-injecting transforms of a tiny app.
 * The engine must keep ok/band under rename, and fail under tautology/skip.
 *
 * On incorporate: `src/metamorphic/transforms.ts`. Fixtures live next to tests
 * and must be excluded from vitest collect (see Cursor_B vitest.config `fixtures/**`).
 */
export function renameIdentifier(src, from, to) {
    const re = new RegExp(`\\b${from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g");
    return src.replace(re, to);
}
/** Replace every assertion call with expect(true).toBe(true). */
export function injectTautology(src) {
    return src
        .replace(/expect\s*\([\s\S]*?\)\s*(?:\.\s*[A-Za-z_$][\w$]*\s*\([\s\S]*?\))+/g, "expect(true).toBe(true)")
        .replace(/assert\s*\.\s*\w+\s*\([\s\S]*?\)/g, "expect(true).toBe(true)");
}
export function wrapTestsInSkip(src) {
    return src.replace(/\b(it|test)\s*\(/g, "$1.skip(");
}
export const HONEST_ADD_SRC = `export function add(a, b) {
  return a + b;
}
`;
export const HONEST_ADD_TEST = `import { add } from "../src/add.js";

it("adds two numbers", () => {
  expect(add(2, 3)).toBe(5);
});
`;
export const MUST_PASS_THROW_SRC = `export function parsePositive(n) {
  if (n < 0) throw new Error("must be positive");
  return n;
}
`;
export const MUST_PASS_THROW_TEST = `import { parsePositive } from "../src/parsePositive.js";

it("rejects negatives", () => {
  expect(() => parsePositive(-1)).toThrow(/positive/);
});
`;
export const MUST_PASS_ASYNC_SRC = `export async function ready() {
  return { ok: true };
}
`;
export const MUST_PASS_ASYNC_TEST = `import { ready } from "../src/ready.js";

it("resolves ok", async () => {
  expect(await ready()).toEqual({ ok: true });
});
`;
