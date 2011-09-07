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
import hmac
import binascii
import urllib
from .utils import *
try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha


from .exceptions import InterfaceError, AuthError
from .utils import *


class AuthManager(object):
    """Auth manager base class
    """
    def setup(self, curl_opener):
        raise NotImplementedError


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



## DEFENITIONS
## Service Provider:
##   A web application that allows access via OAuth.
## User:
##   An individual who has an account with the Service Provider.
## Consumer:
##   A website or application that uses OAuth to access the Service Provider on behalf of the User.
## Protected Resource(s):
##   Data controlled by the Service Provider, which the Consumer can access through authentication.
## Consumer Developer:
##   An individual or organization that implements a Consumer.
## Consumer Key:
##   A value used by the Consumer to identify itself to the Service Provider.
## Consumer Secret:
##   A secret used by the Consumer to establish ownership of the Consumer Key.
## Request Token:
##   A value used by the Consumer to obtain authorization from the User, and exchanged for an Access Token.
## Access Token:
##   A value used by the Consumer to gain access to the Protected Resources on behalf of the User, instead of using the User’s Service Provider credentials.
## Token Secret:
##   A secret used by the Consumer to establish ownership of a given Token.
## OAuth Protocol Parameters:
## Parameters with names beginning with oauth_.

OAUTH_VERSION = '1.0' #OAUHT 2.0
SIGNATURES = ("HMAC-SHA1", "RSA-SHA1", "PLAINTEXT")

class OAuthToken(object):
    pass

class OAuthConsumer(object):
    """Registered application that uses OAuth to access the Service Provider
    on behalf of the User.

    """
    def __init__(self, key, secret):
        # A value used by the Consumer to identify itself to the Service Provider.
        self._key = key
        # A secret used by the Consumer to establish ownership of the Consumer Key.
        self._secret = secret

        if key is None or secret is None:
            raise ValueError("Key and secret must be set.")

# Step 1: Get a request token. This is a temporary token that is used for
# having the user authorize an access token and to sign the request to obtain
# said access token.

# Step 2: Redirect to the provider. Since this is a CLI script we do not
# redirect. In a web application you would redirect the user to the URL
# below.

class OAuth(AuthManager):
    """Auth manager for OAuth
    """
    def __init__(self, consumer):
        if isinstance(consumer, OAuthConsumer):
            self._consumer = consumer
        else:
            self._consumer = OAuthConsumer(*consumer)

    def setup(self, curl_opener):
        pass



class SignatureMethod(object):
    """A way of signing requests.

    The OAuth protocol lets consumers and service providers pick a way to sign
    requests. This interface shows the methods expected by the other `oauth`
    modules for signing requests. Subclass it and implement its methods to
    provide a new way to sign requests.
    """

    def signing_base(self, request, consumer_secret, token_secret):
        """Calculates the string that needs to be signed.

        This method returns a 2-tuple containing the starting key for the
        signing and the message to be signed. The latter may be used in error
        messages to help clients debug their software.

        """
        raise NotImplementedError

    def sign(self, request, consumer_secret, token_secret):
        """Returns the signature for the given request, based on the consumer
        and token_secret also provided.

        You should use your implementation of `signing_base()` to build the
        message to sign. Otherwise it may be less useful for debugging.

        """
        raise NotImplementedError

    def check(self, request, consumer_secret, token_secret, signature):
        """Returns whether the given signature is the correct signature for
        the given consumer and token signing the given request."""
        built = self.sign(request, consumer, token)
        return built == signature


class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HMAC-SHA1'

    def signing_base(self, request, consumer_secret, token_secret=None):
        if not request.get('normalized_url') or request.get('method') is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            url_escape(request['method']),
            url_escape(request['normalized_url']),
            url_escape(request['normalized_parameters']),
        )

        key = '%s&' % url_escape(consumer_secret)
        if token_secret:
            key += url_escape(token_secret)

        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer_secret, token_secret=None):
        """Builds the base signature string.
        """
        key, raw = self.signing_base(request, consumer_secret, token_secret)

        hashed = hmac.new(key, raw, sha)

        # Calculate the digest base 64.
        return binascii.b2a_base64(hashed.digest())[:-1]


class SignatureMethod_PLAINTEXT(SignatureMethod):
    """OAuth PLAINTEXT signature

    oauth_signature is set to the concatenated encoded values
    of the Consumer Secret and Token Secret, separated by a ‘&’ character
    (ASCII code 38), even if either secret is empty. The result MUST be encoded again.
    """

    name = 'PLAINTEXT'

    def signing_base(self, request, consumer_secret, token_secret):
        """Concatenates the consumer key and secret with the token's secret.
        """

        sig = '%s&' % url_escape(consumer_secret)
        if token_secret:
            sig = sig + url_escape(token_secret)
        return sig, sig

    def sign(self, request, consumer_secret, token_secret):
        key, raw = self.signing_base(request, consumer_secret, token_secret)
        return url_escape(raw)
