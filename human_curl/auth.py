#!/usr/bin/env python
# -*- coding:  utf-8 -*-

"""
human_curl.auth
~~~~~~~~~~~~~~~

Authentication module for human curl

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import pycurl

from .exceptions import InterfaceError


class AuthManager(object):
    """Auth manager base class
    """
    pass


class BasicAuth(AuthManager):
    """Basic Auth manager

    HTTP Basic authentication
    """

    def __init__(self, username=None, password=None, *args, **kwargs):
        super(BasicAuth, self).__init__(*args, **kwargs)
        if not username or not password:
            raise InterfaceError("Basic auth required username and password")

        self._username = username
        self._password = password

    def setup(self, curl_opener):
        """Setup BasicAuth for opener
        """
        curl_opener.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
        curl_opener.setopt(pycurl.USERPWD, "%s:%s" % (self._username, self._password))


class DigestAuth(BasicAuth):
    """Digest auth manager

    HTTP Digest authentication manager
    full support of qop == auth and part of qop == auth-int
    auth-int don't create HA1 with entity body
    """

    def __init__(self, username=None, password=None, *args, **kwargs):
        super(DigestAuth, self).__init__(username, password, *args, **kwargs)

    def setup(self, curl_opener):
        """Setup auth method for curl opener
        """
        curl_opener.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
        curl_opener.setopt(pycurl.USERPWD, "%s:%s" % (self._username,
                                                      self._password))

