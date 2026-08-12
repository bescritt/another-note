# Contributing to Another Note

Thanks for your interest. This is a small, deliberately self-contained project,
so the bar for changes is: **don't break the offline path, the test suite, or
the safety model.**

## Running the tests

```bash
pip install cryptography          # only needed for the report path
python3 -m doctest another_note.py
python3 -m unittest test_another_note -v
python3 another_note.py selfcheck
```

All four must pass with zero failures. `test_another_note.py` is a 50-case
stdlib suite that uses synthetic, neutral fixtures — it touches no real
accounts and makes no network calls.

## Hard rules

1. **The `report` safety model is non-negotiable.** Every label must be
   confirmed individually by a human at an interactive prompt, with no
   programmatic override and no pipe input. Never add a flag that bypasses it.
2. **Offline first.** `classify` must work against the bundled `./data`
   filters with no network access. Don't introduce network dependencies into
   the read path.
3. **Privacy-preserving data.** The shipped `.dat` files are bloom filters and
   must stay non-enumerable. Don't add any path that could enumerate accounts.

## License posture

- The upstream Shinigami Eyes algorithm and format knowledge carry the **MIT**
  license (see `LICENSE-MIT`). Keep that notice intact.
- New code, docs, and packaging carry **CC-BY-SA-NC 4.0** (see `LICENSE-CC`).
  Contributions of new code are accepted under those same terms.

## Updating the dataset

The bundled filters in `./data` are versioned upstream. Bump them with:

```bash
python3 another_note.py update -d ./data
```

Commit the new `.dat` files and note the upstream version in `CHANGELOG.md`.
