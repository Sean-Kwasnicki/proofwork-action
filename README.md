# Proofwork — GitHub Action

An independent merge gate for code written by AI agents. It runs on **your**
runner, against **your** checkout, and reports a verdict.

## Install — the gate, reporting mode

Twelve lines. No licence. Read two weeks of pull requests, then set
`fail-on: denied` if the findings are real.

```yaml
# Two weeks of report cards. Then fail-on: denied.
name: proofwork
on: [pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    permissions: { contents: read, pull-requests: write }
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: Sean-Kwasnicki/proofwork-action@ec95f5a
        with: { fail-on: never }
```

## Certificate, verify link and public ledger row

A signed integrity record is a later step and a licence. Use the reusable
workflow — the only route to a public record, and not how you adopt the gate.

```yaml
name: Proofwork
on: [pull_request, push]

jobs:
  proofwork:
    uses: Sean-Kwasnicki/proofwork-action/.github/workflows/gate.yml@v1
    permissions:
      contents: read
      id-token: write
      pull-requests: write
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

That is also why the job needs `id-token: write` on the caller — GitHub will
not let the reusable workflow request it unless the workflow that called it
grants it. The snippet above does. Without it the gate still runs and still
blocks a bad merge; there is simply no record.

## What leaves your repository

Nothing. The gate reads your code where it already is. No source, no diff, and
no findings are uploaded anywhere, and the run writes nothing into your tree.

When a record is requested, what is sent is counts and digests: the verdict,
the score, four totals, the commit, and a hash of the tree. The issuer refuses
a deposit carrying source-shaped fields rather than stripping them, so that
promise cannot quietly stop being true.

Without a licence key the Action runs the same gate and prints every
finding with file and line. A licence is required only to deposit a
signed public record.

## What is in this repository

Compiled JavaScript and the manifest. The engine is developed separately; the
conditions the gate tests for are not published, because an agent that can read
them can be written to satisfy them without doing the work.

Site: https://agent-proofwork.onrender.com/
