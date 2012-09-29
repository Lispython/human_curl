#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Exceptions module for cURL for Humans

:copyright: Copyright 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

from httplib import responses

__all__ = ("HTTPError", "InvalidMethod", "CurlError", "InterfaceError")

class HTTPError(Exception):
    """Exception for failed HTTP request

    :param code: HTTP error integer error code, e. g. 404
    :param message: error message string
    """
    def __init__(self, code, message=None):
        self.code = code
        message = message or responses.get(code, "Unknown")
        Exception.__init__(self, "%d: %s" % (self.code, message))

class InvalidMethod(Exception):
    """Exception raise if `Request.__init__()` get unsupported method
    """

class CurlError(Exception):
    """Exception raise when `pycurl.Curl` raise connection errors

    :param code: HTTP error integer error code, e. g. 404
    :param message: error message string
    """
    def __init__(self, code, message=None):
        self.code = code
        message = message or responses.get(code, "Unknown")
        Exception.__init__(self, "%d: %s" % (self.code, message))

class InterfaceError(Exception):
    """Raises when get not allowed parametr type
    or not allowed parameter
    """

class AuthError(Exception):
    """Raised by auth manager
    """
