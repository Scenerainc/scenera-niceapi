.PHONY: all test_deps clean-venv test format clean clean-tox clean-pyc clean-docs clean-build clean-test docs build

all: test_deps format lint test docs build
	@echo "All passed"

build:
	@TOXENV=build venv/bin/python3 tox

clean:
	-@rm -fr tests/htmlreport/
	-@rm -fr tests/htmlcov/
	-@rm -fr build/
	-@rm -fr dist/
	-@rm -fr src/*.egg
	-@rm -fr src/*.egg-info
	-@rm -fr  docs/build/*
	-@rm -fr  docs/source/plantuml-images/
	-@rm -fr  docs/source/README.rst
	-@rm -fr .tox/
	-@rm -fr .coverage
	-@rm -fr .mypy_cache/
	-@rm -fr .pytest_cache/
	-@find . -name '*.pyc' -delete
	-@find . -name '*.pyo' -delete
	-@find . -name '*~' -delete
	-@find . -name '__pycache__' -delete

venv/bin/python3:
	@/usr/bin/python3 -m venv venv

test_deps: venv/bin/python3
	@venv/bin/python3 -m pip install -U py tox isort black flake8

lint: test_deps
	@TOXENV=flake8,mypy,bandit venv/bin/python3 -m tox

test: test_deps
	@TOXENV=py venv/bin/python3 -m tox

format: test_deps
	@TOXENV=isort,black venv/bin/python3 -m tox

clean-venv:
	-@rm -fr venv/

clean-test:
	-@rm -fr tests/htmlreport/
	-@rm -fr tests/htmlcov/
	-@rm -fr .pytest_cache/

clean-build:
	-@rm -fr build/
	-@rm -fr dist/
	-@rm -fr src/*.egg
	-@rm -fr src/*.egg-info

clean-pyc:
	-@find . -name '*.pyc' -delete
	-@find . -name '*.pyo' -delete
	-@find . -name '*~' -delete
	-@find . -name '__pycache__' -delete

clean-docs:
	-@rm -fr  docs/build/*
	-@rm -fr  docs/source/plantuml-images/
	-@rm -fr  docs/source/README.rst

clean-tox:
	-@rm -rf .tox/

clean-all: clean clean-tox clean-docs clean-pyc clean-build clean-test clean-venv
	@printf "Finished clean\n" 1>&2

docs:
	@TOXENV=docs tox
