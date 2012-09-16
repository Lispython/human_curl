# -*- coding:  utf-8 -*-
"""
human_curl.methods
~~~~~~~~~~~~~~~~~~

HTTP methods functions

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

from .core import Request
from .utils import dispatch_hook

__all__ = ("get", "put", "head", "delete", "post", "options", "request")


def request(method, url, params=None, data=None, headers=None, cookies=None,
            files=None, timeout=None, allow_redirects=False, max_redirects=5, proxy=None,
            auth=None, network_interface=None, use_gzip=None, validate_cert=False,
            ca_certs=None, cert=None, debug=False, user_agent=None, ip_v6=False,
            hooks=None, options=None, callback=None, return_response=True, **kwargs):
    """Construct and sends a Request object. Returns :class `Response`.

    Arguments:

    - `url`: (string) resource url
    - `method`: (string) one of `self.SUPPORTED_METHODS`
    - `data`: (dict, duple, string) data to send as Content-Disposition form-data
    - `params`: (dict, tuple) of GET params (?param1=value1&param2=value2)
    - `headers`: (dict, tuple) of request headers
    - `cookies`: (dict, tuple or CookieJar) of cookies
    - `files`: (dict, tuple or list) of files
       Example:
           (('field_file_name', '/path/to/file.txt'),
           ('field_file_name', open('/path/to/file.txt')),
           ('multiple_files_field', (open("/path/to/file.1.txt"), open("/path/to/file.1.txt"))),
           ('multiple_files_field', ("/path/to/file.1.txt", "/path/to/file.1.txt")))
    - `timeout`: (float) connection time out
    - `connection_timeout`: (float)
    - `allow_redirects`: (bool) follow redirects parametr
    - `proxy`: (dict, tuple or list) of proxies
       Examples:
           ('http', ('127.0.0.1', 9050))
           ('http', ('127.0.0.1', 9050, ('username', 'password'))
           TODO: multiple proxies support?
           (('http', ('127.0.0.1', 9050)),
            ('socks', ('127.0.0.1', 9050, ('username', 'password')))
    - `auth`: (dict, tuple or list) for resource base auth
    - `network_interface`: (str) use given interface for request
    - `use_gzip`: (bool) accept gzipped data
    - `validate_cert`: (bool)
    - `ca_certs`:
    - `cert`: (string) use for client-side certificate authentication
    - `debug`: (bool) use for `pycurl.DEBUGFUNCTION`
    - `user_agent`: (string) user agent
    - `ip_v6`: (bool) use ipv6 protocol
    - `options`: (list, tuple) low level curl options

    Returns:
    - `response`: :Response instance
    """
    args = dict(
        method=method, url=url, params=params, data=data, headers=headers, cookies=cookies,
        files=files, timeout=timeout, allow_redirects=allow_redirects, max_redirects=max_redirects, proxy=proxy,
        auth=auth, network_interface=network_interface, use_gzip=use_gzip, validate_cert=validate_cert,
        ca_certs=ca_certs, cert=cert, debug=debug, user_agent=user_agent, ip_v6=ip_v6, options=options,
        callback=callback, **kwargs)

    # TODO: add hooks
    r = Request(**args)

    # process request before send
    r = dispatch_hook('pre_request', hooks, r)

    if not return_response:
        return r
    r.send()

    # process request after send
    r = dispatch_hook('post_request', hooks, r)

    # process response
    r.response = dispatch_hook('response_hook', hooks, r.response)

    return r.response


def get(url, **kwargs):
    """Sends a GET request. Returns :class: `Response` object

    Arguments:
    - `url`: Resource url
    """
    return request("GET", url, **kwargs)


def post(url, data='', **kwargs):
    """Sends a POST request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    - `data`: vars for send
    """
    return request("POST", url, data=data, **kwargs)


def head(url, **kwargs):
    """Sends a HEAD request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    """
    return request("HEAD", url, **kwargs)


def put(url, data='', **kwargs):
    """Sends a PUT request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    - `data`: vars for send
    """
    return request("PUT", url, data=data, **kwargs)


def patch(url, data='', **kwargs):
    """Sends a PATCH request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    - `data`: update data
    """
    return request("PATCH", url, data=data, **kwargs)


def delete(url, **kwargs):
    """Sends a DELETE request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    """
    return request("DELETE", url, **kwargs)


def options(url, **kwargs):
    """Sends a OPTIONS request. Returns :class: `Response` object.

    Arguments:
    - `url`: Resource url
    """
    return request("OPTIONS", url, **kwargs)
