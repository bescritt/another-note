# Another Note — developer convenience targets.
# No build step; standard library plus `cryptography` (only for `report`).

.PHONY: test doctest selfcheck smoke serve

test:           ## Run the 50-case stdlib unittest suite
	python3 -m unittest test_another_note

doctest:        ## Run the embedded doctest examples
	python3 -m doctest another_note.py

selfcheck:      ## Validate the FNV-1a + bloom math against a synthetic filter
	python3 another_note.py selfcheck

smoke:          ## Offline classify smoke test against bundled data
	python3 another_note.py classify facebook.com/example_page_one

serve:          ## Preview the GitHub Pages site locally
	cd docs && python3 -m http.server 8000

all: doctest test selfcheck smoke
