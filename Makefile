all: clean-pyc test

test:
	python setup.py nosetests --stop --tests tests.py

shell:
	../venv/bin/ipython

audit:
	../venv/bin/python audit

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

find-print:
	grep -r --include=*.py --exclude-dir=venv --exclude=fabfile* --exclude=tests.py --exclude-dir=tests --exclude-dir=commands 'print' ./

mongo-start:
	rm -rf /var/lib/mongodb/mongod.lock
	sudo mongod --fork -f /etc/mongodb.conf --auth --logpath /var/log/mongodb/mongodb.log --logappend
