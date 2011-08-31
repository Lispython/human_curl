========================
Developing and debugging
========================

Create fork and clone to local system.
No need install package for run tests or debugging.

``(venv) $ python setup.py develop``


TESTING
-------

Run tests
==============

Unittests:
``(venv) $ python setup.py test``

Or run by nose test engine

Drop into debugger on errors:

``(venv) $ python setup.py nosetests --pdb --tests tests.py``

Stop running tests after the first error or failure:

``(venv) $ python setup.py nosetests --stop --tests tests.py``


Or you can use you own tests.


CONTRIBUTING
------------

Commit changes into you own github repositury and create pull request
to https://github.com/Lispython/human_curl
