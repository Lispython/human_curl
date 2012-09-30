#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
HUMAN cURL LIBRARY
~~~~~~~~~~~~~~~~~~

cURL wrapper for Human

Features:
    - Fast
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
    - Basic/Digest authentication
    - OAuth support!
    - Debug request and response headers
    - Multicurl support

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

__all__ = ('get', 'put', 'head', 'post', 'delete', 'request', 'options',
           'Request', 'Response', 'get_version', 'AsyncClient', 'async_client')
__author__ = "Alex Lispython (alex@obout.ru)"
__license__ = "BSD, see LICENSE for more details"
__version_info__ = (0, 0, 8)
__build__ = 0x000008
__version__ = ".".join(map(str, __version_info__))
__maintainer__ = "Alexandr Lispython (alex@obout.ru)"


def get_version():
    return __version__

from .methods import get, put, head, post, delete, request, options
from .core import Request, Response
from .exceptions import CurlError, InterfaceError, InvalidMethod, AuthError
from .async import AsyncClient, async_client
