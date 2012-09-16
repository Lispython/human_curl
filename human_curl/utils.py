#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.utils
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Utils module of cURL for Humans

:copyright: Copyright 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import zlib
import time
import urllib
import urlparse
import pycurl
import random
from urllib2 import parse_http_list
from urllib import quote_plus
from logging import getLogger
from Cookie import Morsel
from string import capwords
from os.path import exists as file_exists
from cookielib import CookieJar, Cookie
from types import ListType, DictType, TupleType, FileType, StringTypes

try:
    bytes
except Exception:
    bytes = str

try:
    from urlparse import parse_qs
    parse_qs # placate pyflakes
except ImportError:
    # fall back for Python 2.5
    from cgi import parse_qs

from .exceptions import InterfaceError

__all__ = ('decode_gzip', 'CaseInsensitiveDict', 'from_cookiejar', 'to_cookiejar',
           'morsel_to_cookie', 'data_wrapper', 'make_curl_post_files', 'url_escape',
           'utf8', 'to_unicode', 'parse_authenticate_header', 'parse_authorization_header',
           'WWWAuthenticate', 'Authorization', 'parse_dict_header', 'generate_nonce',
           'generate_timestamp', 'generate_verifier', 'normalize_url', 'normalize_parameters',
           'parse_qs', 'stdout_debug', 'dispatch_hook', 'curry')

logger = getLogger("human_curl.core")

def url_escape(value):
    """Returns a valid URL-encoded version of the given value."""
    """Escape a URL including any /."""
    return urllib.quote(value.encode('utf-8'), safe='~')
#    return quote_plus(utf8(value))

_UTF8_TYPES = (bytes, type(None))
def utf8(value):
    """Converts a string argument to a byte string.

    If the argument is already a byte string or None, it is returned unchanged.
    Otherwise it must be a unicode string and is encoded as utf8.
    """
    if isinstance(value, _UTF8_TYPES):
        return value
    assert isinstance(value, unicode)
    return to_unicode(value).encode("utf-8")

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

    def iteritems(self):
        return ((capwords(k, '-'), v) for k, v in super(CaseInsensitiveDict, self).iteritems())


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



def parse_dict_header(value):
    """Parse key=value pairs from value list
    """
    result = {}
    for item in parse_http_list(value):
        if "=" not in item:
            result[item] = None
            continue
        name, value = item.split('=', 1)
        if value[:1] == value[-1:] == '"':
            value = urllib.unquote(value[1:-1]) # strip " and unquote
        result[name] = value
    return result


def generate_timestamp():
    """Get seconds since epoch (UTC)."""
    return int(time.time())


def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def generate_verifier(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def parse_authenticate_header(header):
    """Parse WWW-Authenticate response header

    WWW-Authenticate: Digest
                 realm="testrealm@host.com",
                 qop="auth,auth-int",
                 nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                 opaque="5ccc069c403ebaf9f0171e9517f40e41"
    """
    if not header:
        return
    try:
        auth_type, auth_info = header.split(None, 1)
        auth_type = auth_type.lower()
    except ValueError, e:
        print(e)
        return
    return WWWAuthenticate(auth_type, parse_dict_header(auth_info))


def parse_authorization_header(header):
    """Parse authorization header and build Authorization object
    """
    if not header:
        return
    try:
        auth_type, auth_info = header.split(None, 1) # separate auth type and values
        auth_type = auth_type.lower()
    except ValueError, e:
        print(e)
        return

    if auth_type == 'basic':
        try:
            username, password = auth_info.decode('base64').split(':', 1)
        except Exception, e:
            return
        return Authorization('basic', {'username': username,
                                       'password': password})
    elif auth_type == 'digest':
        auth_map = parse_dict_header(auth_info)

        required_map = {
            'auth': ("username", "realm", "nonce", "uri", "response", "opaque"),
            'auth-int': ("realm", "nonce", "uri", "qop", "nc", "cnonce", "response", "opaque")}
        required = required_map.get(auth_map.get('qop', 'auth'))

        for key in required:
            if not key in auth_map:
                return
        return Authorization('digest', auth_map)
    elif auth_type == 'oauth':
        auth_map = parse_dict_header(auth_info)
        return Authorization('oauth', auth_map)
    else:
        raise ValueError("Unknown auth type %s" % auth_type)


class WWWAuthenticate(dict):
    """WWWAuthenticate header object
    """

    AUTH_TYPES = ("Digest", "Basic", "OAuth")

    def __init__(self, auth_type='basic', data=None):
        if auth_type.lower() not in [t.lower() for t in self.AUTH_TYPES]:
            raise RuntimeError("Unsupported auth type: %s" % auth_type)
        dict.__init__(self, data or {})
        self._auth_type = auth_type

    @staticmethod
    def from_string(value):
        """Build Authenticate object from header value

        - `value`: Authorization field value
        """
        return parse_authenticate_header(value)

    def to_header(self):
        """Convert values into WWW-Authenticate header value
        """
        d = dict(self)
        return "%s %s" % (self._auth_type.title(), ", ".join("%s=\"%s\"" % (k, v)
                                                             for k, v in d.iteritems()))


class Authorization(dict):
    """Authorization header object
    """

    AUTH_TYPES = ("Digest", "Basic", "OAuth")

    def __init__(self, auth_type='Basic', data=None):
        if auth_type.lower() not in [t.lower() for t in self.AUTH_TYPES]:
            raise RuntimeError("Unsupported auth type: %s" % auth_type)
        dict.__init__(self, data or {})
        self._auth_type = auth_type

    def __str__(self):
        return self.to_header()

    @staticmethod
    def from_string(value):
        """Build Authorization object from header value

        - `value`: Authorization field value
        """
        return parse_authorization_header(value)

    def to_header(self):
        """Convert values into WWW-Authenticate header value
        """
        d = dict(self)
        return "%s %s" % (self._auth_type, ", ".join("%s=\"%s\"" % (k, v)
                                                             for k, v in sorted(d.iteritems())))


    # Digest auth properties http://tools.ietf.org/html/rfc2069#page-4

    realm = property(lambda x: x.get('realm'), doc="""
    A string to be displayed to users so they know which username and
    password to use.""")

    domain = property(lambda x: x.get('domain'), doc="""domain
    A comma-separated list of URIs, as specified for HTTP/1.0.""")



def normalize_url(url):
    if url is not None:
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)

        # Exclude default port numbers.
        if scheme == 'http' and netloc[-3:] == ':80':
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc[-4:] == ':443':
            netloc = netloc[:-4]
        if scheme not in ('http', 'https'):
            raise ValueError("Unsupported URL %s (%s)." % (url, scheme))

        # Normalized URL excludes params, query, and fragment.
        return  urlparse.urlunparse((scheme, netloc, path, None, None, None))
    else:
        return None


def normalize_parameters(url, params=None):
    """Normalize url parameters

    The parameters collected in Section 3.4.1.3 are normalized into a
    single string as follow: http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    """
    items = []
    # Include any query string parameters from the provided URL
    query = urlparse.urlparse(url)[4]
    parameters = parse_qs(utf8(query), keep_blank_values=True)
    for k, v in parameters.iteritems():
        parameters[k] = urllib.unquote(v[0])
    url_items = parameters.items()
    url_items = [(utf8(k), utf8(v)) for k, v in url_items if k != 'oauth_signature' ]
    items.extend(url_items)

    if params:
        for key, value in params.iteritems():
            if key == 'oauth_signature':
                continue
            # 1.0a/9.1.1 states that kvp must be sorted by key, then by value,
            # so we unpack sequence values into multiple items for sorting.
            if isinstance(value, basestring):
                items.append((utf8(key), utf8(value)))
            else:
                try:
                    value = list(value)
                except TypeError, e:
                    assert 'is not iterable' in str(e)
                    items.append((utf8(key), utf8(value)))
                else:
                    items.extend((utf8(key), utf8(item)) for item in value)

    items.sort()
    encoded_str = urllib.urlencode(items)
    # Encode signature parameters per Oauth Core 1.0 protocol
    # spec draft 7, section 3.6
    # (http://tools.ietf.org/html/draft-hammer-oauth-07#section-3.6)
    # Spaces must be encoded with "%20" instead of "+"
    return encoded_str.replace('+', '%20').replace('%7E', '~')



def stdout_debug(debug_type, debug_msg):
    """Print messages into stdout

    - `debug_type`: (int) debug output code
    - `debug_msg`: (str) debug message
    """
    debug_types = ('I', '<', '>', '<', '>')
    if debug_type == 0:
        print('%s' % debug_msg.strip())
    elif debug_type in (1, 2):
        for line in debug_msg.splitlines():
            print('%s %s' % (debug_types[debug_type], line))
    elif debug_type == 4:
        print('%s %r' % (debug_types[debug_type], debug_msg))


def logger_debug(debug_type, debug_msg):
    """Handle debug messages

    - `debug_type`: (int) debug output code
    - `debug_msg`: (str) debug message
    """
    debug_types = ('I', '<', '>', '<', '>')
    if debug_type == 0:
        logger.debug('%s', debug_msg.strip())
    elif debug_type in (1, 2):
        for line in debug_msg.splitlines():
            logger.debug('%s %s', debug_types[debug_type], line)
    elif debug_type == 4:
        logger.debug('%s %r', debug_types[debug_type], debug_msg)



def dispatch_hook(key, hooks, data):
    """Dispatch hooks
    """
    hooks = hooks or dict()

    if key in hooks:
        try:
            data = hooks.get(key).__call__(data) or data
        except Exception, e:
            logger.warn(str(e))
    return data


def curry(fn, *cargs, **ckwargs):
    def call_fn(*fargs, **fkwargs):
        d = ckwargs.copy()
        d.update(fkwargs)
        return fn(*(cargs + fargs), **d)
    return call_fn
