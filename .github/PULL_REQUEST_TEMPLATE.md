## Summary

<!-- What does this PR change, and why? -->

## Safety-model check

- [ ] The `report` human-in-the-loop confirmation is preserved (no override, no pipe input).
- [ ] `classify` / `estimate` / `selfcheck` still run fully offline.

## Verification

- [ ] `python3 -m doctest another_note.py` passes
- [ ] `python3 -m unittest test_another_note` passes (50 cases)
- [ ] `python3 another_note.py selfcheck` passes
- [ ] `make all` is green

## License

- [ ] New code carries CC-BY-NC-SA 4.0; MIT-covered portions keep their notice.
