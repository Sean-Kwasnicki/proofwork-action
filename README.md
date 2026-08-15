# Proofwork — GitHub Action

An independent merge gate for code written by AI agents. It runs on **your**
runner, against **your** checkout, and reports a verdict.

## Certificate, verify link and public ledger row

Use the reusable workflow. This is the only route to a signed public record —
one block, nothing else to install, and nobody at Proofwork involved.

```yaml
name: Proofwork
on: [pull_request, push]

jobs:
  proofwork:
    uses: Sean-Kwasnicki/proofwork-action/.github/workflows/gate.yml@v1
    with:
      subject: "Your Company Ltd"   # exactly as on your licence
    secrets:
      license-key: ${{ secrets.PROOFWORK_LICENSE }}
```

A passing run emails the certificate, publishes a verify link anyone can open
without an account, and adds a row to the public ledger. A failing run blocks
the merge and publishes nothing.

### Why a record needs the workflow and not just the Action

We sign a score we did not compute, so something has to attest that our code
produced it. GitHub's OIDC token names the workflow file that ran, and for a
reusable workflow that is *ours* even though the run is yours. You control the
code being graded; you do not control the grading, and a workflow you wrote
yourself produces a token naming your own file, which the issuer refuses.

That is also why the job needs `id-token: write` — the workflow above sets it
for you. Without it the gate still runs and still blocks a bad merge; there is
simply no record.

## Gate only

Use the Action directly when you want the check and no publishing. It issues
no certificate and adds no ledger row.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: Sean-Kwasnicki/proofwork-action@v1
  with:
    subject: "Your Company Ltd"
    license-key: ${{ secrets.PROOFWORK_LICENSE }}
```

## What leaves your repository

Nothing. The gate reads your code where it already is. No source, no diff, and
no findings are uploaded anywhere, and the run writes nothing into your tree.

When a record is requested, what is sent is counts and digests: the verdict,
the score, four totals, the commit, and a hash of the tree. The issuer refuses
a deposit carrying source-shaped fields rather than stripping them, so that
promise cannot quietly stop being true.

Without a licence key the Action runs the free gate: a real verdict, with the
findings withheld. With one, the report card names every finding and how to
clear it.

## What is in this repository

Compiled JavaScript and the manifest. The engine is developed separately; the
conditions the gate tests for are not published, because an agent that can read
them can be written to satisfy them without doing the work.

Site: https://agent-proofwork.onrender.com/
