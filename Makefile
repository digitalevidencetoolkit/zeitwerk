VENV   := .venv
PY     := $(VENV)/bin/python
STAMP  := $(VENV)/.stamp

.PHONY: help setup test build clean

help:
	@echo "make setup   - create the venv + install dependencies (idempotent)"
	@echo "make test    - run the full suite, incl. the CI python -O pass"
	@echo "make build   - build an sdist + wheel into dist/"
	@echo "make clean   - remove the venv and build artifacts"

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
