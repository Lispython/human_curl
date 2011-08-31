#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.utils
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Utils module of cURL for Humans

:copyright: Copyright 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import zlib
import time
import pycurl
from urllib import quote_plus
from Cookie import Morsel
from os.path import exists as file_exists
from cookielib import CookieJar, Cookie
from types import ListType, DictType, TupleType, FileType, StringTypes

try:
    bytes
except Exception:
    bytes = str

from .exceptions import InterfaceError

__all__ = ('decode_gzip', 'CaseInsensitiveDict', 'from_cookiejar', 'to_cookiejar',
           'morsel_to_cookie', 'data_wrapper', 'make_curl_post_files', 'url_escape',
           'utf8', 'to_unicode')

def url_escape(value):
    """Returns a valid URL-encoded version of the given value."""
    return quote_plus(utf8(value))

_UTF8_TYPES = (bytes, type(None))
def utf8(value):
    """Converts a string argument to a byte string.

    If the argument is already a byte string or None, it is returned unchanged.
    Otherwise it must be a unicode string and is encoded as utf8.
    """
    if isinstance(value, _UTF8_TYPES):
        return value
    assert isinstance(value, unicode)
    return value.encode("utf-8")

_TO_UNICODE_TYPES = (unicode, type(None))
def to_unicode(value):
    """Converts a string argument to a unicode string.

    If the argument is already a unicode string or None, it is returned
    unchanged.  Otherwise it must be a byte string and is decoded as utf8.
    """
    if isinstance(value, _TO_UNICODE_TYPES):
        return value
    assert isinstance(value, bytes)
    return value.decode("utf-8")



def decode_gzip(content):
    """Return gzip-decoded string.

    Arguments:
    - `content`: bytestring to gzip-decode.
    """

    return zlib.decompress(content, 16 + zlib.MAX_WBITS)


class CaseInsensitiveDict(dict):
    """Case-insensitive Dictionary

    For example, `headers['content-encoding']` will return the
    value of a `'Content-Encoding'` response header.
    """

    def __init__(self, *args, **kwargs):
        tmp_d = dict(*args, **kwargs)
        super(CaseInsensitiveDict, self).__init__([(k.lower(), v) for k, v in tmp_d.iteritems()])

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __delitem__(self, key):
        super(CaseInsensitiveDict, self).__delitem__(key.lower())

    def __contains__(self, key):
        return key.lower() in self

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def has_key(self, key):
        return super(CaseInsensitiveDict, self).has_key(key.lower())


def from_cookiejar(cookiejar):
    """Extract cookies dict from cookiejar

    Attributes:
    - `cookiejar`: cookielib.CookieJar instance

    Returns:
    - `cookies`: (dict) dictionary of cookies
    """
    cookies = {}

    # for cookie in cookiejar:
    #    cookies[cookie.name] = cookie.value

    for domain, d_cookies in cookiejar._cookies.iteritems():
        for path, p_cookies in d_cookies.iteritems():
            for cookie in p_cookies.values():
                cookies[cookie.name] = cookie.value
    return cookies


def to_cookiejar(cookies):
    """Build CookieJar object from dict, list or tuple

    Attributes:
    - `cookies`: (dict, list or tuple)

    Returns:
    - `cookiejar`: `CookieJar` instance
    """
    if isinstance(cookies, CookieJar):
        return cookies

    tmp_cookies = []
    if isinstance(cookies, (TupleType, ListType)):
        tmp_cookies = cookies
    elif isinstance(cookies, DictType):
        tmp_cookies = [(k, v) for k, v in cookies.iteritems()]
    else:
        raise ValueError("Unsupported argument")

    cookie_jar = CookieJar()
    for k, v in tmp_cookies:
        cookie = Cookie(
            version=0,
            name=k,
            value=v,
            port=None,
            port_specified=False,
            domain='',
            domain_specified=False,
            domain_initial_dot=False,
            path='/',
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': None},
            rfc2109=False)
        cookie_jar.set_cookie(cookie)

    return cookie_jar


def morsel_to_cookie(morsel):
    """Convert Morsel object to cookielib.Cookie

    Argument:
    - `morsel`: `Cookie.Morsel` instance

    Returns:
    - `cookie`: `cookielib.Cookie` instance
    """
    if not isinstance(morsel, Morsel):
        raise ValueError("morsel mus be Morsel instance")

    # Cookies thinks an int expires x seconds in future,
    # cookielib thinks it is x seconds from epoch,
    # so doing the conversion to string for Cookies
    # fmt = '%a, %d %b %Y %H:%M:%S GMT'
    # sc[name]['expires'] = time.strftime(fmt,
    # time.gmtime(cookie.expires))

    # Morsel keys
    attrs = ('expires', 'path', 'comment', 'domain', 'secure', 'version', 'httponly')
    time_template = "%a, %d-%b-%Y %H:%M:%S GMT"

    tmp = dict(version=0,
               name=None,
               value=None,
               port=None,
               port_specified=False,
               domain='',
               domain_specified=False,
               domain_initial_dot=False,
               path='/',
               path_specified=True,
               secure=False,
               expires=None,
               discard=True,
               comment=None,
               comment_url=None,
               rest={'HttpOnly': None},
               rfc2109=False)

    for attr in attrs:
        try:
            if 'httponly' == attr:
                tmp['rest'] = {'HttpOnly': morsel[attr]}
            elif attr == 'expires':
                # TODO: parse date?
                tmp[attr] = time.mktime(time.strptime(morsel.get(attr), time_template))
                #tmp[attr] = None
            else:
                tmp[attr] = morsel.get(attr, None)
        except (IndexError, Exception), e:
            pass

    tmp['name'] = morsel.key
    tmp['value'] = morsel.value

    try:
        tmp['version'] = int(tmp['version'])
    except ValueError, e:
        tmp['version'] = 1

    cookie = Cookie(**tmp)
    return cookie


def helper(d):
    tmp = []
    for k, v in d:
        if isinstance(v, (TupleType, ListType)):
            for v2 in v:
                tmp.append((k, v2))
        else:
            tmp.append((k, v))
    return tmp


#TODO: use custom MultiValue dict
def data_wrapper(data):
    """Convert data to list and returns
    """
    if isinstance(data, DictType):
        return helper(data.iteritems())
    elif isinstance(data, (TupleType, ListType)):
        return helper(data)
    elif data is None:
        return data
    else:
        raise ValueError("%s argument must be list, tuple or dict, not %s " %
                         ("data_wrapper", type(data)))


def make_curl_post_files(data):
    """Convert parameters dict, list or tuple to cURL style tuple
    """
    if isinstance(data, TupleType):
        iterator = data
    elif isinstance(data, DictType):
        iterator = data.iteritems()
    else:
        raise ValueError("%s argument must be list, tuple or dict, not %s" %
                         ("make_curl_post_files", type(data)))

    def checker(name):
        if file_exists(str(name)):
            return (pycurl.FORM_FILE, str(name))
        else:
            raise RuntimeError("File %s doesn't exist" % v)

    result = []
    for k, v in iterator:
        if isinstance(v, TupleType):
            for k2 in v:
                if isinstance(k2, FileType):
                    result.append((k, checker(k2.name)))
                elif isinstance(k2, StringTypes):
                    result.append((k, checker(k2)))
                else:
                    raise RuntimeError("File %s doesn't exist" % v)
        elif isinstance(v, FileType):
            result.append((k, checker(str(v.name))))
        elif isinstance(v, StringTypes):
            result.append((k, checker(str(v))))
        else:
            raise InterfaceError("Not allowed file value")

    return result
