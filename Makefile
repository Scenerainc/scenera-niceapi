.PHONY: all test format clean clean-tox clean-pyc clean-docs clean-build clean-test docs build

all: format lint test docs build
	@echo "All passed"

build:
	@TOXENV=build tox

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

lint:
	@TOXENV=flake8,mypy,bandit tox

test:
	@TOXENV=py tox

format:
	@TOXENV=isort,black tox

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

docs:
	@TOXENV=docs tox
