/**
 * Law clock — which duties were in force on the day of the run.
 *
 * Citing Article 12 as if it bound a 2026 SaaS agent is the sentence that
 * keeps a competent authority from using this machine. High-risk Annex III
 * obligations apply from 2 December 2027 (Digital Omnibus). Article 50 is live.
 *
 * Never print "compliant". Refs are observations, not determinations.
 */
export const HIGH_RISK_FROM = "2027-12-02";
export const ART_50_FROM = "2026-08-02";
export const LAW_CLOCK = [
    {
        id: "eu.ai-act.art50",
        label: "EU AI Act Art. 50 — transparency (AI interaction / synthetic marking)",
        status: "in_force",
        asOf: ART_50_FROM,
        note: "Live for systems that interact with people or generate content. Function-based, not high-risk only.",
    },
    {
        id: "eu.ai-act.art12",
        label: "EU AI Act Art. 12 — record-keeping",
        status: "delayed",
        asOf: HIGH_RISK_FROM,
        note: "High-risk Annex III. Not generally binding before this date. Observation about logging in the tree, not a legal verdict.",
    },
    {
        id: "eu.ai-act.art14",
        label: "EU AI Act Art. 14 — human oversight",
        status: "delayed",
        asOf: HIGH_RISK_FROM,
        note: "High-risk. Mechanism presence in the tree only.",
    },
    {
        id: "eu.ai-act.art15",
        label: "EU AI Act Art. 15 — accuracy, robustness, cybersecurity",
        status: "delayed",
        asOf: HIGH_RISK_FROM,
        note: "High-risk system performance. This gate does not measure model accuracy.",
    },
    {
        id: "eu.gdpr.art22",
        label: "GDPR Art. 22 — automated individual decisions",
        status: "always",
        asOf: "2018-05-25",
        note: "Looks for a human-review path in code. Cannot decide whether a decision has legal effect.",
    },
    {
        id: "eu.cra",
        label: "Cyber Resilience Act — manufacturer duties on this product",
        status: "in_force",
        asOf: "2026-09-11",
        note: "Applies to Proofwork as a product with digital elements (reporting), not to the customer's integrity band. Essential requirements 2027-12-11.",
    },
    {
        id: "cen.pren18229-1",
        label: "prEN 18229-1 — AI trustworthiness framework, logging",
        status: "draft",
        asOf: "2026-08-20",
        note: "Maps to Art. 12 record-keeping. Observation of a log mechanism in the tree. Not presumption of conformity — the text is not cited in the OJEU.",
    },
    {
        id: "cen.pren18229-2",
        label: "prEN 18229-2 — AI trustworthiness framework, transparency",
        status: "draft",
        asOf: "2026-08-20",
        note: "Maps to Art. 13 / Art. 50 disclosure. Presence of identification in the tree, not a legal determination.",
    },
    {
        id: "cen.pren18229-3",
        label: "prEN 18229-3 — AI trustworthiness framework, human oversight",
        status: "draft",
        asOf: "2026-08-20",
        note: "Maps to Art. 14. Looks for an override / human path in code. Does not measure reaction time or designated-person capacity.",
    },
    {
        id: "cen.pren18229-4",
        label: "prEN 18229-4 — AI trustworthiness framework, accuracy",
        status: "draft",
        asOf: "2026-08-20",
        note: "Maps to Art. 15 accuracy. This gate does not measure model accuracy and must not be cited as if it did.",
    },
    {
        id: "cen.pren18229-5",
        label: "prEN 18229-5 — AI trustworthiness framework, robustness",
        status: "draft",
        asOf: "2026-08-20",
        note: "Maps to Art. 15 robustness. This gate does not measure model robustness.",
    },
    {
        id: "cen.en18286",
        label: "EN 18286:2026 — QMS for AI Act regulatory purposes (Art. 17)",
        status: "draft",
        asOf: "2026-07-01",
        note: "Clause 8.4.1 verification is the nearest analogue to this merge gate. Citation in the OJEU is required before any presumption of conformity. This packet is not that citation.",
    },
];
export function inForceLabel(ref) {
    if (ref.status === "in_force" || ref.status === "always")
        return "in force";
    if (ref.status === "draft")
        return `draft — not cited in the OJEU as of ${ref.asOf}`;
    return `delayed — from ${ref.asOf}`;
}
