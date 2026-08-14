# Proofwork — GitHub Action

An independent merge gate for code written by AI agents. It runs on **your**
runner, against **your** checkout, and reports a verdict.

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

Without a licence key the Action runs the free gate: a real verdict, with the
findings withheld. With one, the report card names every finding and how to
clear it.

## What is in this repository

Compiled JavaScript and the manifest. The engine is developed separately; the
conditions the gate tests for are not published, because an agent that can read
them can be written to satisfy them without doing the work.

Site: https://agent-proofwork.onrender.com/
