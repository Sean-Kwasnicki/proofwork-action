import fs from "node:fs";
import path from "node:path";
/**
 * AI governance checks.
 *
 * Enterprise security questionnaires now ask AI vendors to disclose every model
 * provider that touches customer data. That list is written once, by hand, and
 * then silently goes stale the first time anyone adds a dependency — which is
 * exactly the kind of drift an agent introduces without meaning to.
 *
 * This check is deliberately narrow: it compares the AI providers the code
 * actually depends on against the ones the repo has disclosed. Both sides are
 * mechanically derivable, so the finding is a fact rather than an opinion, and
 * an agent cannot argue its way past it.
 *
 * What it does NOT do: assess whether governance is adequate, or stand in for a
 * conformity assessment. It answers one question — is the disclosure current?
 */
/** Framework requirements this check produces evidence for. */
const FRAMEWORK_REFS = {
    iso42001: ["A.10.2 Allocating Responsibilities", "A.10.3 Suppliers", "A.10.4 Customers"],
    nist: ["GOVERN 6.1", "GOVERN 6.2"],
    eu: ["Art. 13 Transparency and Provision of Information to Deployers"],
};
/**
 * Deliberately a data table, not a chain of conditionals — adding a provider is a
 * one-line change and the matching logic never grows.
 */
const PROVIDER_RULES = [
    { packages: ["@anthropic-ai/sdk", "@anthropic-ai/bedrock-sdk", "@anthropic-ai/vertex-sdk", "anthropic"], name: "Anthropic", kind: "model-provider" },
    { packages: ["openai", "@azure/openai"], name: "OpenAI", kind: "model-provider" },
    { packages: ["@google/generative-ai", "@google-cloud/vertexai"], name: "Google (Gemini / Vertex AI)", kind: "model-provider" },
    { packages: ["@mistralai/mistralai"], name: "Mistral AI", kind: "model-provider" },
    { packages: ["cohere-ai"], name: "Cohere", kind: "model-provider" },
    { packages: ["@aws-sdk/client-bedrock-runtime"], name: "Amazon Bedrock", kind: "model-provider" },
    { packages: ["replicate"], name: "Replicate", kind: "inference-host" },
    { packages: ["@huggingface/inference"], name: "Hugging Face Inference", kind: "inference-host" },
    { packages: ["groq-sdk"], name: "Groq", kind: "inference-host" },
    { packages: ["together-ai"], name: "Together AI", kind: "inference-host" },
    { packages: ["ollama"], name: "Ollama (local inference)", kind: "inference-host" },
    { packages: ["@pinecone-database/pinecone"], name: "Pinecone", kind: "vector-store" },
    { packages: ["weaviate-ts-client", "weaviate-client"], name: "Weaviate", kind: "vector-store" },
    { packages: ["chromadb"], name: "Chroma", kind: "vector-store" },
    { packages: ["@qdrant/js-client-rest"], name: "Qdrant", kind: "vector-store" },
    // "@langchain" covers every package in the scope (core, community, openai, …)
    // via the prefix rule; listing subpackages individually misses new ones.
    { packages: ["langchain", "@langchain"], name: "LangChain", kind: "orchestration" },
    { packages: ["llamaindex"], name: "LlamaIndex", kind: "orchestration" },
    { packages: ["ai"], name: "Vercel AI SDK", kind: "orchestration" },
];
/** Files a disclosure may live in, in the order we prefer to find them. */
const DISCLOSURE_FILES = [
    "AI-SUBPROCESSORS.md",
    "docs/AI-SUBPROCESSORS.md",
    "SUBPROCESSORS.md",
    "docs/SUBPROCESSORS.md",
    ".proofwork/ai-subprocessors.md",
];
function readJson(file) {
    try {
        const raw = fs.readFileSync(file, "utf8");
        // Strip a UTF-8 BOM before parsing. Windows tooling (PowerShell's Out-File,
        // some editors) writes one by default and JSON.parse rejects it — without this
        // the check silently degrades to "skip" on real Windows repos, which is the
        // worst outcome: a governance check that quietly stops looking.
        return JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw);
    }
    catch {
        // A genuinely malformed manifest is not this check's business to report.
        return null;
    }
}
/**
 * Match a dependency name against the rule table. Prefix matching means
 * `@langchain/community` resolves to LangChain without enumerating every subpath,
 * while an exact-name guard stops `ai-utils` matching the `ai` package.
 */
function ruleFor(dependency) {
    return PROVIDER_RULES.find((rule) => rule.packages.some((pkg) => dependency === pkg || dependency.startsWith(`${pkg}/`)));
}
/** Providers the code actually depends on, derived from the package manifest. */
export function detectProviders(root) {
    const manifest = readJson(path.join(root, "package.json"));
    if (!manifest)
        return [];
    const found = new Map();
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
        const deps = manifest[field];
        if (!deps || typeof deps !== "object")
            continue;
        for (const dependency of Object.keys(deps)) {
            const rule = ruleFor(dependency);
            // First sighting wins so `via` names the dependency a reader can go look up.
            if (rule && !found.has(rule.name)) {
                found.set(rule.name, { name: rule.name, kind: rule.kind, via: dependency });
            }
        }
    }
    return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}
export function readDisclosure(root) {
    for (const rel of DISCLOSURE_FILES) {
        const abs = path.join(root, rel);
        try {
            if (fs.existsSync(abs))
                return { file: rel, text: fs.readFileSync(abs, "utf8") };
        }
        catch {
            // Unreadable candidate — keep looking rather than failing the run.
        }
    }
    return { file: null, text: "" };
}
/**
 * Sentences that mention a provider in order to deny using it. Plain substring
 * containment treated "We do not use Mistral AI." as a disclosure of Mistral,
 * which inverted the check: the clearest possible statement that a provider is
 * absent counted as declaring it present.
 */
const NEGATION = /\b(?:do not|don't|does not|doesn't|no longer|never|not)\b[^.]{0,40}\buse[sd]?\b/i;
/**
 * A provider counts as disclosed if its display name appears in the document on a
 * line that is not denying its use. Matching is case-insensitive and ignores the
 * parenthetical qualifier, so "Google (Gemini / Vertex AI)" is satisfied by a
 * disclosure that says "Google".
 */
function isDisclosed(provider, text) {
    const base = provider.name.replace(/\s*\(.*\)\s*/, "").trim().toLowerCase();
    const via = provider.via.toLowerCase();
    // Evaluate line by line so a denial elsewhere in the file cannot mask a genuine
    // listing, and a genuine listing elsewhere cannot be undone by a denial.
    return text.split(/\r?\n/).some((line) => {
        const lower = line.toLowerCase();
        if (!lower.includes(base) && !lower.includes(via))
            return false;
        return !NEGATION.test(line);
    });
}
export function runAiGovernanceChecks(root) {
    const providers = detectProviders(root);
    // No AI dependencies means no AI disclosure obligation. Skip rather than pass:
    // a green tick here would imply we verified something we never looked at.
    if (providers.length === 0) {
        return [
            {
                id: "ai_governance.subprocessors",
                title: "AI subprocessor disclosure",
                status: "skip",
                detail: "No AI model providers detected in package.json — disclosure not applicable",
                evidence: { detected: [], frameworks: FRAMEWORK_REFS },
            },
        ];
    }
    const disclosure = readDisclosure(root);
    const summary = providers.map((p) => `${p.name} (${p.kind}, via ${p.via})`);
    if (!disclosure.file) {
        return [
            {
                id: "ai_governance.subprocessors",
                title: "AI subprocessor disclosure",
                status: "warn",
                detail: `${providers.length} AI provider(s) in use with no disclosure file. ` +
                    `Enterprise buyers ask for this by name. Create AI-SUBPROCESSORS.md listing: ` +
                    providers.map((p) => p.name).join(", "),
                evidence: {
                    detected: summary,
                    disclosure_file: null,
                    searched: DISCLOSURE_FILES,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    const undisclosed = providers.filter((p) => !isDisclosed(p, disclosure.text));
    if (undisclosed.length > 0) {
        return [
            {
                id: "ai_governance.subprocessors",
                title: "AI subprocessor disclosure",
                status: "fail",
                detail: `${undisclosed.length} AI provider(s) used in code but missing from ${disclosure.file}: ` +
                    `${undisclosed.map((p) => `${p.name} (via ${p.via})`).join(", ")}. ` +
                    `A stale subprocessor list is a standard finding in vendor security review.`,
                evidence: {
                    undisclosed: undisclosed.map((p) => p.name),
                    detected: summary,
                    disclosure_file: disclosure.file,
                    frameworks: FRAMEWORK_REFS,
                },
            },
        ];
    }
    return [
        {
            id: "ai_governance.subprocessors",
            title: "AI subprocessor disclosure",
            status: "pass",
            detail: `All ${providers.length} AI provider(s) in use are disclosed in ${disclosure.file}: ` +
                providers.map((p) => p.name).join(", "),
            evidence: {
                detected: summary,
                disclosure_file: disclosure.file,
                frameworks: FRAMEWORK_REFS,
            },
        },
    ];
}
