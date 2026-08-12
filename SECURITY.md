# Security Policy

Another Note is a small, single-file CLI that reimplements the Shinigami Eyes
label filters. This document covers how the tool handles data and how to report
problems responsibly.

## Reporting safety model (by design)

The `report` command is the only network-facing path, and it is deliberately
hardened:

- Every label is confirmed **individually by a human at an interactive prompt**.
  No flag, environment variable, or piped input can skip or automate that step.
- Identifiers that the dataset does not key per account (for example a bare
  `instagram.com/<handle>`) are refused outright.
- When stdin is non-interactive, submission aborts rather than guessing.
- Submissions are hybrid-encrypted (RSA-OAEP-256 + AES-CBC-256) to the upstream
  project's public key, so the transport provider cannot read the contents.

The `classify`, `estimate`, and `selfcheck` commands run **fully offline**
against the bundled bloom filters. They make no network calls.

Anyone who removes, bypasses, or automates the confirmation prompt operates
outside this project's safety model and the upstream intent.

## Data privacy

The shipped `.dat` files are bloom filters. A bloom filter supports membership
testing yet resists enumeration — the underlying account list cannot be
recovered from the files alone.

## Vulnerability reporting

Please report security issues privately through the repository's
[Security advisories](https://github.com/bescritt/another-note/security/advisories/new)
or by opening an issue. Do not include real account identifiers in public
reports.

The port authors run no server. The `report` command posts only to the upstream
endpoint using the upstream encryption scheme; third-party server acceptance of a
non-extension client is outside this distribution's control.
