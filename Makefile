ifndef HTTPHQ_PORT
HTTPHQ_PORT=8891
endif

ifndef HTTPHQ_HOST
HTTPHQ_HOST=127.0.0.1
endif

all: clean-pyc test

test:
	python setup.py nosetests --stop --tests tests.py


run_httphq:
	export HTTP_TEST_URL=http://$(HTTPHQ_HOST):$(HTTPHQ_PORT)/
	httphq server start --port=$(HTTPHQ_PORT) --host=$(HTTPHQ_HOST)&


travis: run_httphq
	python setup.py nosetests --tests tests.py

coverage:
	python setup.py nosetests  --with-coverage --cover-package=human_curl --cover-html --cover-html-dir=coverage_out coverage


shell:
	../venv/bin/ipython

audit:
	python setup.py autdit

version := $(shell sh -c "grep -oP 'VERSION = \"\K[0-9\.]*?(?=\")' ./setup.py")

release: clean-pyc
	git tag -f v$(version) && git push --tags
	python setup.py sdist bdist_wininst upload

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

find-print:
	grep -r --include=*.py --exclude-dir=venv --exclude=fabfile* --exclude=tests.py --exclude-dir=tests --exclude-dir=commands 'print' ./

env:
	./buildenv.sh
	. venv/bin/activate
