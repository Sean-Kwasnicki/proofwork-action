/**
 * Source lexing — telling code from prose.
 *
 * Every detector in this project has the same first problem: a bare word match
 * against raw source cannot tell `expect` in a comment from `expect` in an
 * assertion, or `stripe.charges.create` in an attack fixture from the same call
 * in a payment path. Getting that wrong in one direction misses real findings; in
 * the other it accuses honest work, which is the more expensive mistake.
 *
 * This module is the shared answer. It knows about comments, string literals,
 * template literals, and regex literals, and it reports which of those any given
 * character sits inside — so a caller can require that a match *begins* in code,
 * or in a comment, and never in quoted data.
 *
 * ## Why it is its own file
 *
 * It lived inside `workmanship.ts`, which meant `fakeGreen` and
 * `delegatedAuthority` imported their lexer from an unrelated check. Both the
 * detectors and the scanners kept growing, and the file crossed a thousand lines
 * — flagged for sprawl by this project's own gate, which was correct.
 *
 * The scars in the comments below are worth keeping: each records a way this got
 * it wrong on real code.
 */
/**
 * Strip comments and string literals before looking for an assertion.
 *
 * Matching bare words against raw source is how the detector gets gamed. The word
 * "expect" inside a comment, or "assert" inside a log message, is not an
 * assertion — but a word-boundary regex cannot tell, and an agent that has read
 * the regex will put one there deliberately. Everything below runs on code only.
 *
 * This is a lexical strip, not a parser. It is deliberately conservative: on
 * anything it cannot confidently classify it leaves the text in place, which
 * risks a missed detection rather than a false accusation.
 *
 * **Newlines inside removed regions are preserved.** Every finding this module
 * emits carries a file and a line, and that line is the only part a person acts
 * on. A strip that collapsed a template literal would shift every line number
 * after it, and a report that points at the wrong line is worse than silence —
 * it sends someone to read correct code looking for a defect.
 */
/**
 * Does the `/` at `pos` open a regular expression, or is it division?
 *
 * ## Why this has to exist
 *
 * Both scanners below track quote characters to find string literals. A regex
 * containing a quote — `/"subject":\s*"[^"]*"/` — has quotes that open nothing,
 * and treating one as a string start desynchronises everything after it: real
 * code gets classified as string contents until the next stray quote.
 *
 * The damage is not theoretical and not small. It made a test with two genuine
 * assertions report as hollow, because both `expect` calls fell inside a phantom
 * string. A blocking finding on correct work is the one failure this product
 * cannot afford: an honest agent doing its job must pass, and regexes containing
 * quotes are ordinary in any code that parses, validates, or sanitises text.
 *
 * ## How the ambiguity is resolved
 *
 * `/` is division after a value and a regex after an operator, so the decision
 * needs the previous meaningful character. After an identifier, a number, or a
 * closing bracket, a `/` divides; after `(`, `,`, `=`, `:`, `[`, `!`, `&`, `|`,
 * `?`, `{`, `}`, `;`, or a return, it opens a pattern.
 *
 * This is a heuristic, not a parser, and it is wrong in the same rare places
 * every lexer without a full grammar is wrong — `a++ /re/` and a few keyword
 * cases. It is deliberately biased: when unsure it treats the `/` as division and
 * leaves the text alone, which risks a missed detection rather than a false
 * accusation.
 */
function opensRegex(src, pos) {
    let k = pos - 1;
    while (k >= 0 && /\s/.test(src[k]))
        k -= 1;
    if (k < 0)
        return true; // start of file — nothing to divide
    const prev = src[k];
    if (/[)\]]/.test(prev))
        return false; // (a + b) / 2
    if (/[A-Za-z0-9_$]/.test(prev)) {
        // An identifier or number ends a value, so `/` divides — unless the word is a
        // keyword that cannot be divided, in which case a pattern follows.
        let end = k + 1;
        while (k >= 0 && /[A-Za-z0-9_$]/.test(src[k]))
            k -= 1;
        const word = src.slice(k + 1, end);
        return /^(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await)$/.test(word);
    }
    return true; // an operator or punctuation precedes it
}
/** Advance past a regex literal starting at `pos`, returning the index after it. */
function skipRegex(src, pos) {
    let i = pos + 1;
    let inClass = false;
    while (i < src.length) {
        const c = src[i];
        if (c === "\\") {
            i += 2;
            continue;
        }
        // A `/` inside a character class does not close the literal: /[/]/ is valid.
        if (c === "[")
            inClass = true;
        else if (c === "]")
            inClass = false;
        else if (c === "/" && !inClass)
            return i + 1;
        else if (c === "\n")
            return pos + 1; // unterminated — treat the slash as ordinary
        i += 1;
    }
    return pos + 1;
}
export function stripNonCode(src) {
    let out = "";
    let i = 0;
    const keepNewlines = (from, to) => {
        for (let k = from; k < to && k < src.length; k += 1)
            if (src[k] === "\n")
                out += "\n";
    };
    while (i < src.length) {
        const c = src[i];
        const next = src[i + 1];
        if (c === "/" && next === "/") {
            while (i < src.length && src[i] !== "\n")
                i += 1;
            continue; // the newline itself is copied on the next pass
        }
        if (c === "/" && next === "*") {
            const start = i;
            i += 2;
            while (i < src.length && !(src[i] === "*" && src[i + 1] === "/"))
                i += 1;
            i += 2;
            keepNewlines(start, i);
            continue;
        }
        // Blanked like a string. Beyond keeping quotes inside the pattern from
        // opening a phantom literal, this fixes brace counting: `/\d{2}/` used to
        // contribute an opening brace that no `}` ever closed, so a `catch` block
        // containing such a pattern was measured to the wrong end.
        if (c === "/" && opensRegex(src, i)) {
            const end = skipRegex(src, i);
            out += '""';
            keepNewlines(i, end);
            i = end;
            continue;
        }
        if (c === '"' || c === "'" || c === "`") {
            const quote = c;
            const start = i;
            i += 1;
            while (i < src.length && src[i] !== quote) {
                if (src[i] === "\\")
                    i += 1; // skip the escaped character, not just the slash
                i += 1;
            }
            i += 1;
            out += '""'; // keep a placeholder so tokens either side stay separated
            keepNewlines(start, i);
            continue;
        }
        out += c;
        i += 1;
    }
    return out;
}
/** What kind of text a character sits in. Values are the mask's alphabet. */
export const SPAN_CODE = 0;
export const SPAN_STRING = 1;
export const SPAN_COMMENT = 2;
/**
 * Index-aligned mask: is the character at position i code, a string literal, or
 * a comment?
 *
 * Wholesale stripping is too blunt for callers whose rules legitimately read
 * string contents — `vi.mock('./relative')` is only a finding *because* of what
 * the string says, and blanking it deletes the signal along with the noise.
 *
 * The precise question is not "does this line contain a string?" but "does this
 * match *begin* inside one?". A match starting at `vi.mock` begins in code and
 * counts; a match starting inside `'it.skip(x)'` begins in a literal and does
 * not. This mask lets a caller ask exactly that and nothing more.
 *
 * ## Why comments are a separate value from strings
 *
 * They were the same value once, and it made this gate fail its own repository.
 *
 * Some rules are *about* comments — a line reading `// force pass so CI goes
 * green` is the confession, and a rule that skipped comments could never see it.
 * Those rules therefore ignored the mask entirely, which meant they also fired on
 * `const src = "// force pass"` inside the very test file that proves the rule
 * works. The detector's own fixtures were read as the offence they detect.
 *
 * Collapsing "not code" into one value forces a choice between missing real
 * confessions and flagging every fixture. Distinguishing the two lets a caller
 * say precisely what it means: a comment is a place where an admission can live,
 * a string literal is data — quoting an offence is not committing one.
 */
export function nonCodeMask(text) {
    const mask = new Uint8Array(text.length);
    let i = 0;
    const fill = (from, to, kind) => {
        for (let k = from; k < to && k < text.length; k += 1)
            mask[k] = kind;
    };
    /**
     * Inside a comment, backticks quote.
     *
     * Documentation that explains a rule has to name the pattern it detects, and
     * the convention for that everywhere in this codebase — and in most others — is
     * markdown inline code. A doc comment reading "silenced every rule whose purpose
     * is to read a comment: `// force pass`, `// @ts-ignore`" is describing the
     * offence, not committing it.
     *
     * This is the same principle already applied to string literals, using prose's
     * own quotation mark. Without it, the only way to document a rule is to avoid
     * writing down what it matches, which makes the rules unmaintainable and pushes
     * authors toward blanket suppressions.
     *
     * A lone backtick has no closing partner and marks nothing, so ordinary prose is
     * unaffected.
     *
     * Pairing stops at the end of the line, which is both how inline code actually
     * works and what closes an evasion: in a block comment, an opening backtick that
     * could reach across lines would let a stray character mask every admission
     * until the next one.
     */
    const quoteSpansInComment = (from, to) => {
        let k = from;
        while (k < to) {
            if (text[k] !== "`") {
                k += 1;
                continue;
            }
            const nl = text.indexOf("\n", k + 1);
            const lineEnd = nl === -1 || nl > to ? to : nl;
            const close = text.indexOf("`", k + 1);
            if (close === -1 || close >= lineEnd) {
                // Unpaired on this line. Skip to the next line and keep looking.
                k = lineEnd + 1;
                continue;
            }
            fill(k + 1, close, SPAN_STRING);
            k = close + 1;
        }
    };
    while (i < text.length) {
        const c = text[i];
        const next = text[i + 1];
        if (c === "/" && next === "/") {
            const start = i;
            while (i < text.length && text[i] !== "\n")
                i += 1;
            fill(start, i, SPAN_COMMENT);
            quoteSpansInComment(start, i);
            continue;
        }
        if (c === "/" && next === "*") {
            const start = i;
            i += 2;
            while (i < text.length && !(text[i] === "*" && text[i + 1] === "/"))
                i += 1;
            i += 2;
            fill(start, i, SPAN_COMMENT);
            quoteSpansInComment(start, i);
            continue;
        }
        /**
         * A regular expression is data, like a string.
         *
         * Consuming it whole stops a quote inside the pattern from being read as
         * opening a string. Marking the interior as data is the second half of the
         * same idea, and it was learned the same way: a security scanner containing
         * `/refunds\.create|payouts\.create/` was reported as an agent that issues
         * refunds and creates payouts. The pattern names the thing it looks for —
         * describing a money call is not making one.
         *
         * The delimiters stay code so a caller anchoring on the slash still sees it.
         */
        if (c === "/" && opensRegex(text, i)) {
            const end = skipRegex(text, i);
            fill(i + 1, end - 1, SPAN_STRING);
            i = end;
            continue;
        }
        /**
         * A template literal is data, except where it isn't.
         *
         * `${…}` is an interpolation: the text inside is evaluated, so it is code in
         * the fullest sense. Marking a whole template as string made that code
         * invisible, and the hole was immediately usable — an agent reading its
         * owner's credential as `` `Bearer ${user.oauth_token}` `` matched no rule,
         * because the only part naming the credential sat in a span the scanners had
         * been told to ignore. Anything an author wanted hidden could be wrapped in a
         * template and interpolated.
         *
         * The interpolated expression is therefore left as code, and the literal text
         * around it is still data.
         */
        if (c === "`") {
            i += 1; // past the opening backtick, which stays code
            while (i < text.length && text[i] !== "`") {
                if (text[i] === "\\") {
                    mask[i] = SPAN_STRING;
                    mask[i + 1] = SPAN_STRING;
                    i += 2;
                    continue;
                }
                if (text[i] === "$" && text[i + 1] === "{") {
                    // Skip the expression, leaving it SPAN_CODE. Braces are counted so a
                    // nested object literal does not end the interpolation early.
                    let depth = 1;
                    i += 2;
                    while (i < text.length && depth > 0) {
                        if (text[i] === "{")
                            depth += 1;
                        else if (text[i] === "}")
                            depth -= 1;
                        i += 1;
                    }
                    continue;
                }
                mask[i] = SPAN_STRING;
                i += 1;
            }
            i += 1;
            continue;
        }
        if (c === '"' || c === "'") {
            const quote = c;
            const start = i;
            i += 1;
            while (i < text.length && text[i] !== quote) {
                if (text[i] === "\\")
                    i += 1;
                i += 1;
            }
            i += 1;
            // Mark the interior only. The opening quote stays code so a match anchored
            // on the quote itself is still visible to the caller.
            fill(start + 1, i, SPAN_STRING);
            continue;
        }
        i += 1;
    }
    return mask;
}
/** Byte offset at which each line starts, for mapping a line match into the mask. */
export function lineOffsets(text) {
    const offsets = [0];
    for (let i = 0; i < text.length; i += 1) {
        if (text[i] === "\n")
            offsets.push(i + 1);
    }
    return offsets;
}
