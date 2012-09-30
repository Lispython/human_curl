#!/usr/bin/env python
# -*- coding:  utf-8 -*-

"""
human_curl.auth
~~~~~~~~~~~~~~~

Authentication module for human curl

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""
import binascii
import hmac
from types import StringTypes, ListType

try:
    import pycurl2 as pycurl
except ImportError:
    import pycurl

from urllib import urlencode

import methods as hurl
from .exceptions import InterfaceError
from .utils import *


try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha


class AuthManager(object):
    """Auth manager base class
    """

    def __init__(self):
        self._parent_request = None
        self._debug = None

    def setup(self, curl_opener):
        raise NotImplementedError

    def setup_request(self, request):
        """Setup parent request for current auth manager
        """
        self._parent_request = request
        if hasattr(request, '_debug_curl'):
            self._debug = request._debug_curl


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


DEFAULT_OAUTH_VERSION = '1.0' #OAUHT 2.0


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
        built = self.sign(request, consumer_secret, token_secret)
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


class OAuthAuthorization(Authorization):
    """OAuth authorization header value
    """

    REQUIRED_FIELDS = ('oauth_consumer', 'oauth_nonce', 'oauth_signature', 'oauth_signature_method',
                       'oauth_timestamp')

    def __init__(self, data=None):
        super(OAuthAuthorization, self).__init__('OAuth', data)

    oauth_consumer = property(lambda x: x.get('oauth_consumer'), doc='''
    ''')
    oauth_token = property(lambda x: x.get('oauth_token'), doc='''
    ''')
    oauth_signature_method = property(lambda x: x.get('oauth_signature_method'), doc='''
    ''')

    oauth_signature = property(lambda x: x.get('oauth_signature'), doc='''
    ''')
    oauth_timestamp = property(lambda x: x.get('oauth_timestamp'), doc='''
    ''')

    oauth_nonce = property(lambda x: x.get('oauth_nonce'), doc='''
    ''')
    oauth_version = property(lambda x: x.get('oauth_version'), doc='''
    ''')


class OAuthToken(object):
    """OAuth token wrapper

    Request Token:
    Used by the Consumer to ask the User to authorize access
    to the Protected Resources. The User-authorized Request Token is exchanged
    for an Access Token, MUST only be used once, and MUST NOT
    be used for any other purpose. It is RECOMMENDED that Request Tokens
    have a limited lifetime.

    Access Token:
    Used by the Consumer to access the Protected Resources
    on behalf of the User. Access Tokens MAY limit access to certain
    Protected Resources, and MAY have a limited lifetime.
    Service Providers SHOULD allow Users to revoke Access Tokens.
    Only the Access Token SHALL be used to access the Protect Resources.
    """

    def __init__(self, key, secret):
        self._key = key
        self._secret = secret
        self._callback = None
        self._callback_confirmed = None
        self._verifier = None

        if self._key and self._secret:
            # ready for request to protected resources
            self._state = 7
        else:
            self._state = 1

    @property
    def state(self):
        return self._state


class OAuthConsumer(object):
    """Registered application that uses OAuth to access the
    Service Provider on behalf of the User.

    """

    def __init__(self, key, secret):
        # A value used by the Consumer to identify itself to the Service Provider.
        self._key = key
        # A secret used by the Consumer to establish ownership of the Consumer Key.
        self._secret = secret

        if key is None or secret is None:
            raise ValueError("Key and secret must be set.")


class OAuthManager(AuthManager):
    """Auth manager for OAuth
    """

    SIGNATURES_METHODS = {
        # 'RSA-SHA1': SignatureMethod_RSA_SHA1
        'HMAC-SHA1': SignatureMethod_HMAC_SHA1,
        'PLAINTEXT': SignatureMethod_PLAINTEXT}

    def __init__(self, consumer, token=None, request_token_url=None,
                 authorize_url=None, access_token_url=None, signature_method=None,
                 version=DEFAULT_OAUTH_VERSION):

        if isinstance(consumer, OAuthConsumer):
            self._consumer = consumer
        else:
            self._consumer = OAuthConsumer(*consumer)

        if isinstance(token, OAuthToken):
            self._token = token
        elif token is None:
            self._token = None
        else:
            self._token = OAuthToken(*token)


        if isinstance(signature_method, SignatureMethod):
            self._signature_method = signature_method
        elif signature_method is None:
            self._signature_method = SignatureMethod_PLAINTEXT()
        elif isinstance(signature_method, StringTypes):
            if signature_method.upper() in self.SIGNATURES_METHODS.keys():
                self._signature_method = self.SIGNATURES_METHODS[signature_method.upper()]()
            else:
                raise RuntimeError('Unknown signature method')
        elif issubclass(signature_method, SignatureMethod):
            self._signature_method = signature_method()
        else:
            raise RuntimeError('Unknown signature method')


        # if consumer key, secret specified and tokens secret, key
        # 3 if tmp_token and tmp_token_secret is given
        # 5 if verifier
        # 7 if token_key and token_secret
        self._state = self._token.state if self._token else 1
        self._realm = None

        self._verifier = None

        # oauth challenge urls
        self._request_token_url = request_token_url
        self._authorize_url = authorize_url
        self._access_token_url = access_token_url

        self._version = version
        if self._state == 1 and (not self._request_token_url or
                                 not self._authorize_url or
                                 not self._access_token_url):
            raise RuntimeError('Challenge urls required if state is 1')

        self._parent_request = None
        self._debug = None

        self._tmp_token_key = None
        self._tmp_token_secret = None

    @property
    def state(self):
        return self._state

    def verify(self, verifier):
        """Verify access request
        """
        self._verifier = verifier
        self._state = 5

    def auth_header(self, realm=None):
        params = {
            'oauth_consumer_key': self._consumer._key,
            'oauth_timestamp': generate_timestamp(),
            'oauth_signature_method': self._signature_method.name,
            'oauth_nonce': generate_nonce(),
            'oauth_version': str(self._version),
            'oauth_token': self._token._key,
            'realm': realm or normalize_url(self._parent_request._build_url())
            }

        params['oauth_signature'] = self._signature_method.sign({
            'method': self._parent_request._method.upper(),
            'normalized_url': normalize_url(self._parent_request._build_url()),
            'normalized_parameters': normalize_parameters(self._parent_request._build_url())},
                                                                self._consumer._secret, self._token._secret)
        return Authorization('OAuth', params)


    def access_request(self):
        """Create request to access token endpoint
        """
        params = {
            'oauth_verifier': self._verifier,
            'oauth_token': self._tmp_token_key,
            'oauth_consumer_key': self._consumer._key,
            'oauth_timestamp': generate_timestamp(),
            'oauth_signature_method': self._signature_method.name,
            'oauth_nonce': generate_nonce(),
            'oauth_version': str(self._version),
            'realm': normalize_url(self._access_token_url)}

        params['oauth_signature'] = self._signature_method.sign({
            'method': 'POST',
            'normalized_url': normalize_url(self._access_token_url),
            'normalized_parameters': normalize_parameters(self._access_token_url)
            }, self._consumer._secret, self._tmp_token_secret)

        r = hurl.post(self._access_token_url,
                      data=urlencode(params), debug = self._debug)

        ## r = hurl.post(self._access_token_url,
        ##               headers={"Authorization": str(OAuthAuthorization(params))},
        ##               debug=self._debug)

        if r.status_code in (200, 201):
            tokens = parse_qs(r.content)
            self._token = OAuthToken(tokens['oauth_token'][0], tokens['oauth_token_secret'][0])
            self._state = 7

    def request_token(self):
        """Send request to request_token endpoint
        """

        params = {
            'oauth_consumer_key': self._consumer._key,
            'oauth_timestamp': generate_timestamp(),
            'oauth_signature_method': self._signature_method.name,
            'oauth_nonce': generate_nonce(),
            'oauth_version': str(self._version),
            'realm': normalize_url(self._request_token_url)}

        params['oauth_signature'] = self._signature_method.sign({
            'method': 'POST',
            'normalized_url': normalize_url(self._request_token_url),
            'normalized_parameters': normalize_parameters(self._request_token_url)},
                                                                self._consumer._secret, None)

        r = hurl.post(self._request_token_url,
                      data=urlencode(params), debug=self._debug)

        ## r = hurl.post(self._request_token_url,
        ##             headers={"Authorization": str(OAuthAuthorization(params))},
        ##             debug=self._debug)

        if r.status_code in (200, 201):
            tokens = parse_qs(r.content)
            self._tmp_token_key = tokens['oauth_token'][0]
            self._tmp_token_secret = tokens['oauth_token_secret'][0]
            self._state = 3 # oauth_token and oauth_secret is given

    @property
    def confirm_url(self):
        return "%s?oauth_token=%s" % (self._authorize_url, self._tmp_token_key)

    def setup(self, curl_opener):
        if self._state == 7:
            if isinstance(self._parent_request._headers, ListType):
                self._parent_request._headers.append(('Authorization', str(self.auth_header())))
            else:
                self._parent_request._headers = data_wrapper({'Authorization': str(self.auth_header())})
            ## curl_opener.setopt(pycurl.HTTPHEADER, ["%s: %s" % (capwords(f, "-"), v) for f, v
            ##                                   in CaseInsensitiveDict(self._parent_request._headers).iteritems()])
            #curl_opener.setopt(pycurl.HEADER, {'Authorization': str(self.auth_header())})
        else:
            raise AuthError('OAuth require token_key and token_secret')
