VENV   := .venv
PY     := $(VENV)/bin/python
STAMP  := $(VENV)/.stamp

# make deploy: the witness to update, as an ssh destination, and what to update it to.
WITNESS ?= admin@zeitwerk-witness
REF     ?= main

.PHONY: help setup test build clean deploy deploy-check

help:
	@echo "make setup   - create the venv + install dependencies (idempotent)"
	@echo "make test    - run the full suite, incl. the CI python -O pass"
	@echo "make build   - build an sdist + wheel into dist/"
	@echo "make clean   - remove the venv and build artifacts"
	@echo "make deploy  - update the witness at WITNESS to REF (default: main), over ssh"
	@echo "make deploy-check - what make deploy would change, changing nothing"

setup: $(STAMP)
	@echo "Environment ready. Try 'make test'."

$(STAMP): pyproject.toml
	@echo "Setting up $(VENV) ..."
	git submodule update --init
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -e submodules/python-opentimestamps -e .
	touch $(STAMP)

test: setup
	$(PY) -m unittest discover tests
	$(PY) -O -m unittest discover tests

build: setup
	$(VENV)/bin/pip install -q build
	$(PY) -m build

clean:
	rm -rf $(VENV) dist *.egg-info

# Runs this checkout's deploy/update.sh on the witness, which needn't have it yet.
deploy:
	ssh $(WITNESS) sudo sh -s -- $(REF) < deploy/update.sh

deploy-check:
	ssh $(WITNESS) sudo sh -s -- --dry-run $(REF) < deploy/update.sh
