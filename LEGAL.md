# LEGAL

## Licenses

### Upstream — MIT (Shinigami Eyes)

The algorithm and format knowledge reimplemented here — the FNV-1a hash contract,
the bloom-filter byte layout, the identifier normalization rules, and the
submit-vote encryption envelope — originate from the Shinigami Eyes browser
extension (github.com/shinigami-eyes/shinigami-eyes). That material carries the
MIT License. A verbatim copy of the MIT text lives in this distribution's
`LICENSE-MIT` file and binds the MIT-covered portions.

### This port — CC-BY-NC-SA 4.0

The new code in `another_note.py`, plus the documentation, packaging, and legal
text, carry the Creative Commons Attribution-NonCommercial-ShareAlike 4.0
International license (CC-BY-NC-SA 4.0). That license grants permission to
share and adapt the new material under the same terms, provided the user gives
appropriate credit, shares alike, and refrains from commercial use.

### License relationship

The MIT license governs the upstream-covered portions; CC-BY-NC-SA governs the
additions. The NonCommercial term does not revoke any permission the MIT license
grants for the MIT-covered portions. Where the two meet, the upstream MIT terms
control the MIT-covered material.

## Disclaimers

1. **No warranty.** The software ships "AS IS", without warranty of any kind,
   express or implied, including (without limit) warranties of merchantability,
   fitness for a particular purpose, and non-infringement. The authors and
   copyright holders accept no liability for any claim, damage, or other
   liability arising from the use of the software.

2. **Label accuracy.** A "neither" result denotes only that a key sits absent
   from the shipped dataset; it states nothing about any person. A positive label
   reflects a third-party crowd-sourced signal, not a verified fact. The tool
   makes no representation about the truth of any label.

3. **Data resists mining.** The shipped `.dat` files store bloom filters. A
   bloom filter supports membership testing yet resists enumeration; no process
   recovers the underlying account list from the files. Anyone who claims
   to have extracted the full account list from the `.dat` files has not done so
   from this data alone.

4. **Reporting endpoint.** The `report` command posts only to the upstream
   server endpoint using the upstream encryption scheme. The authors of this port
   control no server. Server-side acceptance of a non-extension client stays
   unverified by this distribution.

5. **Human confirmation stays mandatory.** The `report` command prompts a human
   operator for each entry and accepts no programmatic override. Anyone who
   removes, bypasses, or automates that prompt operates outside the project's
   safety model and the upstream intent.

6. **No legal advice.** This document summarizes license posture; it constitutes
   no legal advice. Consult a qualified attorney for advice on specific use.

## Comprehensive audit results

| Area | Method | Result |
|------|--------|--------|
| Hash contract (FNV-1a, UTF-16, signed 32-bit) | unit tests + doctests | pass |
| Bloom layout (combined two-part sharding, k=20/21, split 287552) | round-trip + layout tests | pass |
| Identifier normalization (all domain branches) | 50-test unittest suite | pass |
| Non-keyable inputs (Instagram, garbage) | Sentinel assertion | pass |
| Encryption envelope shape (RSA-OAEP-256 + AES-CBC-256, version 100037) | envelope-shape test | pass |
| Wire label tokens (`t-friendly` / `transphobic`) | verified vs extension source | pass |
| Reporting safety (per-item prompt, no override, refuse non-keyable) | interactive + abort tests | pass |
| Self-check math (synthetic filter, no real accounts) | `selfcheck` command | 0 mismatches |
| Offline operation (bundled filters, no network for classify) | real classify run | pass |
| Line coverage (every function exercised) | 50-test suite + doctests | pass |
| Packaging (permissions 0755, cross-platform shebang) | `stat` + execute | pass |

The audit ran against the bundled filters (version 26073100, dated 2026-07-31)
and the synthetic self-check fixture. The live POST path stayed unexecuted; the
envelope matches the extension contract by construction, yet third-party server
acceptance of a non-extension client remains unverified by this distribution.

## Acknowledgements

We thank the Shinigami Eyes authors and contributors. Please direct support to
the original authors via the project's GitHub repository; we located no verified
first-party donation URL at writing time.
