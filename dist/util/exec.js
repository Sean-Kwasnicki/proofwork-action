import { execFileSync } from "node:child_process";
export function tryExec(cmd, args, cwd, timeoutMs = 8_000) {
    try {
        // trimEnd only — full trim breaks `git status --porcelain` (leading space in XY codes)
        const out = execFileSync(cmd, args, {
            cwd,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
            timeout: timeoutMs,
            windowsHide: true,
            maxBuffer: 8 * 1024 * 1024,
        }).replace(/\s+$/, "");
        return { ok: true, out };
    }
    catch (err) {
        const e = err;
        const out = `${e.stdout ?? ""}${e.stderr ?? e.message ?? ""}`.trim();
        return { ok: false, out };
    }
}
export function isCi() {
    return Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
}
