.PHONY: all test lib-test docs-test modules-test coverage dist upload clean doc deps

all:
	@exit 1

deps:
	pip install -e .

deps-dev: deps

test: format-test
	byexample -l python --ff  iasm/*.py
	byexample -l shell,iasm --timeout 8  README.md


## Formatting
#  ==========

format:
	yapf -vv -i --style=.style.yapf --recursive iasm/

format-test:
	yapf -vv --style=.style.yapf --diff --recursive iasm/
#
##

## Packaging and clean up
#  ======================

dist:
	rm -Rf dist/ build/ *.egg-info
	python setup.py sdist bdist_wheel
	rm -Rf build/ *.egg-info

upload: dist
	twine upload dist/*.tar.gz dist/*.whl

clean_test:
	@rm -f .coverage .coverage.work.*

clean: clean_test
	rm -Rf dist/ build/ *.egg-info
	rm -Rf build/ *.egg-info
	find . -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -f README.rst

#
##
