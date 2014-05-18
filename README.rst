Welcome to human_curl's documentation!
======================================

Curl requests for Humans

human_curl allow you to send  **HEAD**, **GET**, **POST**, **PUT**,
**OPTIONS**, and **DELETE** HTTP requests.

.. image:: https://secure.travis-ci.org/Lispython/human_curl.png
	   :target: https://secure.travis-ci.org/Lispython/human_curl

Features
--------

- Custom HTTP headers
- Request data/params
- Multiple file uploading
- Async requests!
- Cookies support (dict or CookieJar)
- Redirection history
- Proxy support (http, https, socks4/5)
- Custom interface for request!
- Auto decompression of GZipped content
- Unicode URL support
- Request timers and another info
- Certificate validation
- ipv6 support
- Basic/Digest authentication
- OAuth support!
- Debug request and response headers
- .netrc support


Usage
-----


**Simple get request**

    >>> import human_curl as requests # python-requests.org compatibile
    >>> # import human_curl as hurl # unfortunately hurl.it keeps this name :-)
    >>> r = hurl.get('http://h.wrttn.me/basic-auth/test_username/test_password',
    ... auth=('test_username', 'test_password'))
    >>> r.status_code
    200
    >>> r.content
    '{"username": "test_username", "password": "test_password", "authenticated": true}'

**Cookies and headers**

    >>> import human_curl as hurl # python-requests.org compatibile
    >>> r = hurl.get("http://h.wrttn.me/cookies/set/ajfwjlknefjrrf/fkjwnfklrnjge")
    >>> r.cookies
        {'ajfwjlknefjrrf': 'fkjwnfklrnjge'}
    >>> r.headers['etag']
        bf21a9e8fbc5a3846fb05b4fa0859e0917b2202f
    >>> r.headers
        {'connection': 'keep-alive',
         'content-length': '2',
         'content-type': 'text/html; charset=UTF-8',
         'date': 'Mon, 05 Sep 2011 20:28:47 GMT',
         'etag': 'bf21a9e8fbc5a3846fb05b4fa0859e0917b2202f',
         'server': 'LightBeer/0.568'}




**Send files and variables**

    >>> import human_curl as hurl
    >>> r = hurl.post('http://h.wrttn.me/post', files=(('file_1', '/tmp/testfile1.txt'),
    ... ('file2', open('/tmp/testfile2.txt'))), data={'var_name': 'var_value'})
    >>> r.status_code
    201


**Redirects**

    >>> import human_curl as hurl
    >>> r = hurl.get('http://h.wrttn.me/redirect/4', allow_redirects=True)
    >>> r.status_code
    200
    >>> print(r.history)
	['http://h.wrttn.me/redirect/3', 'http://h.wrttn.me/redirect/2',
     'http://h.wrttn.me/redirect/1', 'http://h.wrttn.me/redirect/end']
    >>> print(r.url)
	http://h.wrttn.me/redirect/end


**Auth managers**

    >>> import human_curl as hurl
    >>> from human_curl.auth import BasicAuth, DigestAuth
    >>> auth_manager = DigesAuth('username', 'password')
    >>> r = hurl.post('http://h.wrttn.me/digest-auth/auth/username/password',
    ... auth=auth_manager)
    >>> r.status_code
    200
    >>> basic_auth_manager = BasicAuth('username', 'password')
    >>> r = hurl.post('http://h.wrttn.me/basic-auth/username/password',
    ... auth=basic_auth_manager)
    >>> r.status_code
    200
    >>> oauth_manager = OAuthManager((CONSUMER_KEY, CONSUMER_SECRET), (TOKEN_KEY, TOKEN_SECRET))
    >>> r = hurl.get('http://oauth-protected.com/resource', auth=oauth_manager)
    >>> r.status_code
    200

**Debug requests**

    >>> import human_curl as hurl
    >>> # stdout_debug(debug_type, debug_msg)
    >>> r = hurl.get("https://h.wrttn.me/basic-auth/username/password",
    ... debug=stdout_debug, allow_redirects=False,
    ... auth=("username", "password"))
    >>> print(r.status_code)
    200


**Async requests**

    >>> from human_curl.async import AsyncClient
    >>> async_client = AsyncClient(success_callback=lambda **kw: print kw,
    ... fail_callback=lambda **kw: print kw)
    >>> async_client.get('http://h.wrttn.me/get')
    >>> async_client.get('http://httpbin.org/get',
    ... success_callback=lambda **kw: print("success!"),
    ... fail_callback=lambda **kw: print("fail!")
    >>> async_client.start()



TODO
----

- curl command generation?


INSTALLATION
------------

To use human_curl use pip or easy_install:

`pip install human_curl`

or

`easy_install human_curl`


CONTRIBUTE
----------

Fork https://github.com/Lispython/human_curl/ , create commit and pull request to ``develop``.


SEE ALSO
--------

If you don't like cURL (why?), try to use `python-requests`_.

.. _`python-requests`: http://python-requests.org
