VENV := $(HOME)/.venv/snr-timeline
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest

.PHONY: venv install test run clean

venv:
	python3 -m venv $(VENV)

install: venv
	$(VENV)/bin/pip install -r requirements.txt

test: install
	$(PYTEST) test_snr_timeline.py -v

run: install
	$(PYTHON) snr_timeline.py .

clean:
	rm -rf .pytest_cache __pycache__
