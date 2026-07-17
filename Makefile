VENV   := .venv
PY     := $(VENV)/bin/python
STAMP  := $(VENV)/.stamp

.PHONY: setup test demo build clean

setup: $(STAMP)

$(STAMP): pyproject.toml
	git submodule update --init
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -e submodules/python-opentimestamps -e .
	touch $(STAMP)

test: setup
	$(PY) -m unittest discover tests
	$(PY) -O -m unittest discover tests

demo: setup
	$(PY) examples/lost_receipt_demo.py

build: setup
	$(VENV)/bin/pip install -q build
	$(PY) -m build

clean:
	rm -rf $(VENV) dist *.egg-info
