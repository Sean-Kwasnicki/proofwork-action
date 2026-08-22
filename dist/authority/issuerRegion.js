/**
 * Where the issuer process claims to run.
 *
 * An authority packet is only a filing if it was sealed in the Union.
 * Standing up eu-central-1 is operations. Refusing to call a US-region
 * signature an EU filing is the engineering half, and it is this file.
 *
 * Local and test issuers are signed so the artefact can still be checked,
 * and they are labelled `unverified-local` so nobody files them as one.
 */
const EU_EXACT = new Set([
    "eu",
    "europe",
    "eea",
]);
const EU_PREFIX = /^(eu[-_]|europe[-_])/i;
const EU_CLOUD = [
    "westeurope",
    "northeurope",
    "germanywestcentral",
    "germanynorth",
    "francecentral",
    "francesouth",
    "swedencentral",
    "switzerlandnorth",
    "switzerlandwest",
    "polandcentral",
    "italynorth",
    "spaincentral",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "europe-west1",
    "europe-west3",
    "europe-west4",
    "europe-west9",
    "europe-north1",
    "europe-central2",
];
export function classifyIssuerRegion(raw) {
    const region = (raw ?? "").trim().toLowerCase();
    if (!region || region === "local" || region === "test" || region === "dev") {
        return "unverified-local";
    }
    if (EU_EXACT.has(region) || EU_PREFIX.test(region) || EU_CLOUD.includes(region)) {
        return "eu";
    }
    return "outside-eu";
}
export function issuerRegionFromEnv(env = process.env) {
    const region = (env.PROOFWORK_ISSUER_REGION ?? "local").trim() || "local";
    return { region, jurisdiction: classifyIssuerRegion(region) };
}
/** An officer can file the packet only when the issuer is in the Union. */
export function isAuthorityFiling(jurisdiction) {
    return jurisdiction === "eu";
}
