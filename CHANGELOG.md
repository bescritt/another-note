# Changelog

All notable changes to this distribution are documented here. The format is
loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Recovered `test_another_note.py` (50-case stdlib unittest suite) and wired it
  into CI — the suite the README and LEGAL already described but that had been
  dropped from the shipping archive.
- GitHub Actions CI: doctests + the 50-case suite + offline CLI self-check and
  classify smoke across Python 3.10–3.13 on Linux/macOS/Windows.
- Dual-license clarity: `LICENSE-MIT` (upstream Shinigami Eyes, MIT) and
  `LICENSE-CC` (this port, CC-BY-SA-NC 4.0).
- GitHub Pages landing site under `docs/`.

### Changed
- `another_note.py` is now committed with the executable bit set (0755), as the
  LEGAL audit requires.

## [2026-07-31] — Bundled dataset

- Filters version `26073100` (dated 2026-07-31), the newest available at build
  time, shipped in `data/transgender_friendly.dat` and
  `data/transgender_averse.dat`.
- Initial public distribution of the single-file CLI: `classify`, `report`,
  `estimate`, `update`, and `selfcheck` subcommands.
