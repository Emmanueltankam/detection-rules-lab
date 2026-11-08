.PHONY: install check test coverage convert all

install:
	pip install -r requirements.txt

check:
	sigma check --fail-on-issues rules/

test:
	pytest -v

coverage:
	python tools/build_coverage.py

convert:
	bash tools/convert.sh dist

all: check test coverage convert
