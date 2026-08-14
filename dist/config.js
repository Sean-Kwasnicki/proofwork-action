import fs from "node:fs";
import path from "node:path";
const DEFAULTS = {
    failOnWarn: false,
    strictAuth: false,
    strictIntegrity: false,
    maxIdenticalFailures: 3,
    skipChecks: [],
};
export function loadConfig(root) {
    const candidates = ["proofwork.config.json", ".proofwork/config.json"];
    for (const rel of candidates) {
        const p = path.join(root, rel);
        if (!fs.existsSync(p))
            continue;
        try {
            const raw = JSON.parse(fs.readFileSync(p, "utf8"));
            const maxFail = Number(raw.maxIdenticalFailures ?? DEFAULTS.maxIdenticalFailures);
            return {
                failOnWarn: Boolean(raw.failOnWarn ?? DEFAULTS.failOnWarn),
                strictAuth: Boolean(raw.strictAuth ?? DEFAULTS.strictAuth),
                strictIntegrity: Boolean(raw.strictIntegrity ?? DEFAULTS.strictIntegrity),
                maxIdenticalFailures: Number.isFinite(maxFail) && maxFail >= 2 ? Math.floor(maxFail) : DEFAULTS.maxIdenticalFailures,
                skipChecks: Array.isArray(raw.skipChecks) ? raw.skipChecks.map(String) : [],
            };
        }
        catch {
            return { ...DEFAULTS };
        }
    }
    return { ...DEFAULTS };
}
