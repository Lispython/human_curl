.. human_curl documentation master file, created by
   sphinx-quickstart on Thu Sep  1 01:41:40 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to human_curl's documentation!
======================================

Curl requests for Humans

human_curl allow you to send  **HEAD**, **GET**, **POST**, **PUT**,
**PATCH**, and **DELETE** HTTP requests.

Features
--------

- Custom HTTP headers
- Request data/params
- Multiple file uploading
- Cookies support (dict or CookieJar)
- Redirection history
- Proxy support (http, https, socks4/5)
- Custom interface for request!
- Auto decompression of GZipped content
- Unicode URL support
- Request timers and another info
- Certificate validation
- ipv6 support


Usage
-----


**Simple get request**

    >>> import human_curl as requests # python-requests.org compatibile
    >>> r = requests.get('http://h.wrttn.me/basic-auth/test_username/test_password', auth=('test_username', 'test_password'))
    >>> r.status_code
    200
    >>> r.content
    '{"username": "test_username", "password": "test_password", "authenticated": true}'


**Send files and variables**

    >>> import human_curl as requests
    >>> r = requests.post('http://h.wrttn.me/post', files=(('file_1', '/tmp/testfile1.txt'),
    ... ('file2', open('/tmp/testfile2.txt'))), data={'var_name': 'var_value'})
	...
    >>> r.status_code
    201


**Redirects**

    >>> import human_curl as requests
    >>> r = requests.get('http://h.wrttn.me/redirect/4', allow_redirects=True)
    >>> r.status_code
    200
    >>> print(r.history)
	['http://h.wrttn.me/redirect/3', 'http://h.wrttn.me/redirect/2', 'http://h.wrttn.me/redirect/1', 'http://h.wrttn.me/redirect/end']
    >>> print(r.url)
	http://h.wrttn.me/redirect/end



TODO
----

- async client
- curl command generation?


INSTALLATION
------------

To use human_curl  use pip or easy_install:

`pip install human_curl`

or

`easy_install human_curl`


CONTRIBUTE
----------

Fork https://github.com/Lispython/human_curl/ , create commit, create pull request.



Contents:

.. toctree::
   :maxdepth: 2

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

