   .-"      "-.
  /            \
 |              |
 |,  .-.  .-.  ,|
 | )(_o/  \o_)( |
 |/     /\     \|
 (_     ^^     _)
  \__|IIIIII|__/
   | \IIIIII/ |
   \          /
    `--------`
<p align="center">
  <img src="assets/hero.png" alt="Another Note — a watchful shinigami eye rendered in glowing lines, with teal and crimson signal accents" width="720">
</p>

<p align="center">
  <b>Another Note</b> — a self-contained, cross-platform CLI that reimplements the
  Shinigami Eyes social-profile label filters from the shipped bloom-filter data.
</p>

# Another Note

Another Note reimplements the Shinigami Eyes social-profile label filters as one
self-contained, cross-platform command-line script. The tool reads two shipped
bloom filters and reports, for a given social-profile identifier, which label the
dataset carries — or "neither" (the key sits absent from the data; this denotes a
coverage gap, never a verdict about any person).

The dataset takes the form of a bloom filter — a fixed-size bit array plus k hash
functions. A bloom filter answers membership queries ("Does X carry a label?")
yet resists inversion; one cannot enumerate the listed accounts from the shipped
data. Outbound reporting uses hybrid encryption (RSA-OAEP-256 plus AES-CBC-256)
to the project's public key, so the cloud provider cannot read the contents.
These design choices carry over from the upstream project.

## Acknowledgements

Another Note ports the Shinigami Eyes browser extension
(github.com/shinigami-eyes/shinigami-eyes). That project crowdsourced signals
about which social profiles stay safe versus unsafe for transgender people, while
storing data as non-enumerable bloom filters and encrypting outbound reports so
the underlying account list could never face data-mining.

We thank the original Shinigami Eyes authors and contributors for the design, the
privacy-preserving architecture, and the public dataset.

Please support the original authors. We located no verified first-party donation
URL at writing time; the canonical contact channel remains the project's GitHub
repository and issue tracker:

    https://github.com/shinigami-eyes/shinigami-eyes

## Description

- Single file: `another_note.py`. No build step. No package install.
- Pure standard library plus `cryptography` (the latter only for `report`).
- Bundled filters ship inside `./data/` (version 26073100, dated 2026-07-31 —
  the newest available at build time). The tool runs fully offline against the
  bundled data.
- Cross-platform: runs on Linux, macOS, and Windows with Python 3.10+.

## Usage

    # Read identifiers / raw URLs (arguments, flags, or a STDIN pipe)
    python3 another_note.py classify facebook.com/example_page_one
    python3 another_note.py classify --url https://twitter.com/example_handle_one
    python3 another_note.py classify --twitter example_handle_one --facebook example_page_two
    cat list.txt | python3 another_note.py classify
    python3 another_note.py classify --json facebook.com/example_page_one
    python3 another_note.py classify --fail-on-unsupported https://instagram.com/foo   # exit 2

    # Coverage sanity signal
    python3 another_note.py estimate

    # Submit labels — interactive, per-item, NO override (never via pipe)
    python3 another_note.py report --dry-run "facebook.com/example_page_one:transgender_averse"
    python3 another_note.py report "facebook.com/x:transgender_friendly" "facebook.com/y:transgender_averse"

    # Math self-check (synthetic, no real accounts)
    python3 another_note.py selfcheck

    # Polite, cadence-gated filter refresh
    python3 another_note.py update -d ./data

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | runtime / usage error, or report POST failed |
| 2 | at least one input became a non-keyable domain/URL (`--fail-on-unsupported`) |
| 3 | reporting aborted (no interactive confirmation available) |

### Options

`-v/--verbose`, `-q/--quiet`, `-c/--config <file>`, `-d/--data-dir <dir>`.

## Reporting — safety model

`report` builds the same hybrid-encryption envelope the extension uses
(RSA-OAEP-256 plus AES-CBC-256, keyed to the project's public key) and POSTs it
to `https://shini-api.xyz/submit-vote`. Before any network call:

1. Each entry normalizes through the identifier sanitizer. Non-keyable
   identifiers (e.g. a bare `instagram.com/<handle>`, which the dataset does not
   key per account) face refusal outright.
2. For every remaining entry, the operator receives an individual prompt and must
   type `yes`. No flag, environment variable, or pipe skips this step. When stdin
   lacks interactivity, the submission aborts rather than guessing.

The wire label tokens use the upstream server's expected JSON keys `t-friendly`
and `transphobic` (verified from extension source); they appear only at the
server boundary.

## Tests

    python3 -m doctest another_note.py          # embedded examples
    python3 test_another_note.py                # 50-test stdlib unittest suite

The suite stays self-contained (synthetic neutral fixtures; `selfcheck`
synthesizes its own filter and validates the hash math against itself — no real
accounts, no network, no Node dependency).

## License

See `LEGAL.md` for the full license text, disclaimers, and audit results. In
brief: the upstream Shinigami Eyes algorithm and format knowledge carry the MIT
license; the new code in `another_note.py` carries CC-BY-NC-SA 4.0.
