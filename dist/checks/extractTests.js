import { stripNonCode } from "./sourceLexer.js";
const TEST_OPENER = /\b(?:it|test)\s*(?:\.\w+)?\s*\(\s*['"`]/;
/**
 * Same brace-walk as Cursor_B `findHollowTests`. Single-line
 * `it("x", () => { expect(1).toBe(1) })` is captured because the walk
 * starts on the opener line, not the line after it.
 */
export function extractTests(text) {
    const lines = stripNonCode(text).split(/\r?\n/);
    const out = [];
    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i] ?? "";
        if (!TEST_OPENER.test(line))
            continue;
        const nameMatch = /(?:it|test)\s*(?:\.\w+)?\s*\(\s*(['"`])(.*?)\1/.exec(line);
        const nameHint = nameMatch?.[2] ?? "";
        let depth = 0;
        let started = false;
        let body = "";
        let end = i;
        scan: for (let j = i; j < lines.length && j < i + 200; j += 1) {
            for (const ch of lines[j] ?? "") {
                if (ch === "{") {
                    depth += 1;
                    if (depth === 1) {
                        started = true;
                        continue;
                    }
                }
                else if (ch === "}") {
                    depth -= 1;
                    if (depth === 0) {
                        end = j;
                        break scan;
                    }
                }
                if (started)
                    body += ch;
            }
            if (started)
                body += "\n";
            end = j;
        }
        out.push({ line: i + 1, nameHint, body });
        i = end;
    }
    return out;
}
export function bodyLooksEmpty(body) {
    const code = stripNonCode(body);
    return !code.replace(/[\s"']/g, "").trim();
}
