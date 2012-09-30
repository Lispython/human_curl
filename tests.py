#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.tests
~~~~~~~~~~~~~~~~

Unittests for human_curl

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""
from __future__ import with_statement

import os
import time
import pycurl2 as pycurl
import cookielib
from Cookie import Morsel
import json
import uuid
from random import randint, choice
from string import ascii_letters, digits
import logging
from urlparse import urljoin
import unittest
import urllib
from types import TupleType, ListType, FunctionType, DictType
from urllib import urlencode

import human_curl as requests
from human_curl import Request, Response
from human_curl import AsyncClient
from human_curl.auth import *
from human_curl.utils import *

from human_curl.exceptions import (CurlError, InterfaceError)

logger = logging.getLogger("human_curl.test")

## async_logger = logging.getLogger("human_curl.async")
## async_logger.setLevel(logging.DEBUG)

## # Add the log message handler to the logger
## # LOG_FILENAME = os.path.join(os.path.dirname(__file__), "debug.log")
## # handler = logging.handlers.FileHandler(LOG_FILENAME)
## handler = logging.StreamHandler()

## formatter = logging.Formatter("%(levelname)s %(asctime)s %(module)s [%(lineno)d] %(process)d %(thread)d | %(message)s ")

## handler.setFormatter(formatter)

## async_logger.addHandler(handler)


TEST_METHODS = (
    ('get', requests.get),
    ('post', requests.post),
    ('head', requests.head),
    ('delete', requests.delete),
    ('put', requests.put),
    ('options', requests.options))

# Use https://github.com/Lispython/httphq
if 'HTTP_TEST_URL' not in os.environ:
    os.environ['HTTP_TEST_URL'] = 'http://h.wrttn.me'

if 'HTTPS_TEST_URL' not in os.environ:
    os.environ['HTTPS_TEST_URL'] = 'https://h.wrttn.me'

HTTP_TEST_URL = os.environ.get('HTTP_TEST_URL')
HTTPS_TEST_URL = os.environ.get('HTTPS_TEST_URL')


def build_url(*parts):
    return urljoin(HTTP_TEST_URL, "/".join(parts))

def build_url_secure(*parts):
    return urljoin(HTTPS_TEST_URL, "/".join(parts))

TEST_SERVERS = (build_url, build_url_secure)

def stdout_debug(debug_type, debug_msg):
    """Print messages
    """
    debug_types = ('I', '<', '>', '<', '>')
    if debug_type == 0:
        print('%s' % debug_msg.strip())
    elif debug_type in (1, 2):
        for line in debug_msg.splitlines():
            print('%s %s' % (debug_types[debug_type], line))
    elif debug_type == 4:
        print('%s %r' % (debug_types[debug_type], debug_msg))


def random_string(num=10):
    return ''.join([choice(ascii_letters + digits) for x in xrange(num)])


class BaseTestCase(unittest.TestCase):

    @staticmethod
    def random_string(num=10):
        return random_string(10)

    def random_dict(self, num=10):
        return dict([(self.random_string(10), self.random_string(10))for x in xrange(10)])

    def request_params(self):
        data = self.random_dict(10)
        data['url'] = build_url("get")
        data['method'] = 'get'

        return data


class RequestsTestCase(BaseTestCase):

    def test_build_url(self):
        self.assertEquals(build_url("get"), HTTP_TEST_URL + "/" + "get")
        self.assertEquals(build_url("post"), HTTP_TEST_URL + "/" + "post")
        self.assertEquals(build_url("redirect", "3"), HTTP_TEST_URL + "/" + "redirect" + "/" + "3")

    def tests_invalid_url(self):
        self.assertRaises(ValueError, requests.get, "wefwefwegrer")

    def test_url(self):
        self.assertEquals(requests.get(build_url("get")).url, build_url("get"))

    def test_request(self):
        for method, method_func in TEST_METHODS:
            r = method_func(build_url(method))
            self.assertTrue(isinstance(r, Response))

    def test_HTTP_GET(self):
        r = requests.get(build_url("get"))
        self.assertEquals(r.status_code, 200)

    def test_HTTP_POST(self):
        r = requests.post(build_url("post"))
        self.assertEquals(r.status_code, 201)

    def test_HTTP_HEAD(self):
        r = requests.head(build_url("head"))
        self.assertEquals(r.status_code, 200)

    def test_HTTP_PUT(self):
        r = requests.put(build_url("put"))
        self.assertEquals(r.status_code, 200)
        r2 = requests.put(build_url("put"),
                          data='kcjbwefjhwbcelihbflwkh')
        self.assertEquals(r2.status_code, 200)

    def test_HTTP_DELETE(self):
        r = requests.delete(build_url("delete"))
        self.assertEquals(r.status_code, 200)

    def test_HTTP_OPTIONS(self):
        r = requests.options(build_url("options"))
        self.assertEquals(r.status_code, 200)

    def test_HEADERS(self):
        import string
        headers = (("test-header", "test-header-value"),
                   ("Another-Test-Header", "kjwbrlfjbwekjbf"))

        r = requests.get(build_url("headers"), headers=headers)
        self.assertEquals(r.status_code, 200)

        r_json = json.loads(r.content)
        for field, value in headers:
            self.assertEquals(r_json.get(string.capwords(field, "-")), value)

    def test_PARAMS(self):
        params = {'q': 'test param'}
        r = requests.get(build_url("get""?test=true"), params=params)
        self.assertEquals(r.status_code, 200)
        args = json.loads(r.content)['args']
        self.assertEquals(args['q'][0], params['q'])
        self.assertEquals(args["test"][0], "true")

    def test_POST_DATA(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        r = requests.post(build_url('post'),
                          data={random_key: random_value})
        self.assertEquals(r.status_code, 201)

    def test_PUT_DATA(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        r = requests.put(build_url('put'),
                          data={random_key: random_value})
        self.assertEquals(r.status_code, 200)

    def test_POST_RAW_DATA(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        data = "%s:%s" % (random_key, random_value)
        r = requests.post(build_url('post'),
                          data=data)
        self.assertEquals(r.status_code, 201)
        self.assertTrue(data in r.content)

    def test_PUT_RAW_DATA(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        data = "%s:%s" % (random_key, random_value)
        r = requests.put(build_url('put'),
                          data=data)
        self.assertEquals(r.status_code, 200)
        self.assertTrue(data in r.content)

    def test_FILES(self):
        files = {'test_file': open('tests.py'),
                 'test_file2': open('README.rst')}
        r = requests.post(build_url('post'),
                          files=files)
        json_response = json.loads(r.content)
        self.assertEquals(r.status_code, 201)
        for k, v in files.items():
            self.assertTrue(k in json_response['files'].keys())

    def test_POST_DATA_and_FILES(self):
        files = {'test_file': open('tests.py'),
               'test_file2': open('README.rst')}
        random_key1 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value1 = "value_" + uuid.uuid4().get_hex()
        random_key2 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value2 = "value_" + uuid.uuid4().get_hex()
        r = requests.post(build_url('post'),
                          data={random_key1: random_value2,
                                random_key2: random_value2},
                          files=files)

        self.assertEquals(r.status_code, 201)

    def test_PUT_DATA_and_FILES(self):
        files = {'test_file': open('tests.py'),
                 'test_file2': open('README.rst')}
        random_key1 = "key_" + uuid.uuid4().get_hex()[:10]
        random_key2 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value2 = "value_" + uuid.uuid4().get_hex()
        r = requests.put(build_url('put'),
                          data={random_key1: random_value2,
                                random_key2: random_value2},
                          files=files)

        self.assertEquals(r.status_code, 200)

    def test_cookies_jar(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        random_key2 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value2 = "value_" + uuid.uuid4().get_hex()

        cookies = ((random_key, random_value),
                   (random_key2, random_value2))

        cookies_jar = cookielib.CookieJar()

        r1 = requests.get(build_url("cookies", "set", random_key, random_value),
                     cookies=cookies_jar)
        self.assertEquals(r1.cookies[random_key], random_value)
        requests.get(build_url("cookies", "set", random_key2, random_value2),
                     cookies=cookies_jar)
        for cookie in cookies_jar:
            if cookie.name == random_key:
                self.assertEquals(cookie.value, random_value)

        r3 = requests.get(build_url('cookies'), cookies=cookies_jar)
        json_response = json.loads(r3.content)
        for k, v in cookies:
            self.assertEquals(json_response[k], v)

    def test_send_cookies(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value = "value_" + uuid.uuid4().get_hex()
        random_key2 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value2 = "value_" + uuid.uuid4().get_hex()

        cookies = ((random_key, random_value),
                   (random_key2, random_value2))

        r = requests.get(build_url('cookies'), cookies=cookies)
        #                          debug=stdout_debug)
        json_response = json.loads(r.content)
        self.assertEquals(json_response[random_key], random_value)


    def test_basic_auth(self):
        username =  uuid.uuid4().get_hex()
        password =  uuid.uuid4().get_hex()
        auth_manager = BasicAuth(username, password)

        r = requests.get(build_url('basic-auth', username, password),
                         auth=auth_manager)
        self.assertEquals(r.status_code, 200)
        json_response = json.loads(r.content)
        self.assertEquals(json_response['password'], password)
        self.assertEquals(json_response['username'], username)
        self.assertEquals(json_response['auth-type'], 'basic')


    def test_digest_auth(self):
        username = uuid.uuid4().get_hex()
        password =  uuid.uuid4().get_hex()
        auth_manager = DigestAuth(username, password)

        r = requests.get(build_url('digest-auth/auth/', username, password),
                         auth=auth_manager, allow_redirects=True)
        self.assertEquals(r.status_code, 200)
        json_response = json.loads(r.content)
        self.assertEquals(json_response['password'], password)
        self.assertEquals(json_response['username'], username)
        self.assertEquals(json_response['auth-type'], 'digest')


    def test_auth_denied(self):
        username = "hacker_username"
        password = "hacker_password"
        http_auth = (username, password)

        r = requests.get(build_url('basic-auth', "username", "password"), auth=http_auth)
        self.assertEquals(r.status_code, 401)

    def test_multivalue_params(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value1 = "value_" + uuid.uuid4().get_hex()
        random_value2 = "value_" + uuid.uuid4().get_hex()
        r = requests.get(build_url("get"),
                         params={random_key: (random_value1, random_value2)})

        self.assertEquals(build_url("get?%s" %
                                    urlencode(((random_key, random_value1), (random_key, random_value2)))), r.url)

        json_response = json.loads(r.content)
        self.assertTrue(random_value1 in json_response['args'][random_key])
        self.assertTrue(random_value2 in json_response['args'][random_key])

    def test_multivalue_post_data(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value1 = "value_" + uuid.uuid4().get_hex()
        random_value2 = "value_" + uuid.uuid4().get_hex()
        r = requests.post(build_url("post"),
                         data={random_key: (random_value1, random_value2)})

        json_response = json.loads(r.content)
        self.assertTrue(random_value1 in json_response['args'][random_key])
        self.assertTrue(random_value2 in json_response['args'][random_key])

    def test_redirect(self):
        r = requests.get(build_url("redirect", '3'), allow_redirects=True)
        self.assertEquals(r.status_code, 200)
        self.assertEquals(len(r.history), 3)
        self.assertEquals(r.url, build_url("redirect/end"))
        self.assertEquals(r._request_url, build_url("redirect/3"))
        self.assertRaises(CurlError, requests.get, build_url("redirect", '7'),
                          allow_redirects=True)

    def test_gzip(self):
        r = requests.get(build_url("gzip"), use_gzip=True)
        self.assertEquals(r.headers['Content-Encoding'], 'gzip')
        json_response = json.loads(r.content)
        self.assertEquals(json_response['gzipped'], True)

    def test_response_info(self):
        r = requests.get(build_url("get"))

    def test_unicode_domains(self):
        r = requests.get("http://➡.ws/pep8")
        self.assertEquals(r.url, 'http://xn--hgi.ws/pep8')

    def test_hooks(self):
        def pre_hook(r):
            r.pre_hook = True

        def post_hook(r):
            r.post_hook = True

        def response_hook(r):
            r._status_code = 700
            return r

        r1 = requests.get("http://h.wrttn.me/get", hooks={'pre_request': pre_hook,
                                                          'post_request': post_hook})
        self.assertEquals(r1._request.pre_hook, True)
        self.assertEquals(r1._request.post_hook, True)

        r2 = requests.get("http://h.wrttn.me/get", hooks={'response_hook': response_hook})
        self.assertEquals(r2._status_code, 700)


    def test_json_response(self):
        random_key = "key_" + uuid.uuid4().get_hex()[:10]
        random_value1 = "value_" + uuid.uuid4().get_hex()
        random_value2 = "value_" + uuid.uuid4().get_hex()
        r = requests.get(build_url("get"),
                         params={random_key: (random_value1, random_value2)})

        self.assertEquals(build_url("get?%s" %
                                    urlencode(((random_key, random_value1), (random_key, random_value2)))), r.url)

        json_response = json.loads(r.content)
        self.assertTrue(isinstance(r.json, (dict, DictType)))
        self.assertEquals(json_response, r.json)
        self.assertTrue(random_value1 in r.json['args'][random_key])
        self.assertTrue(random_value2 in r.json['args'][random_key])

class ResponseTestCase(BaseTestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class RequestTestCase(BaseTestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class UtilsTestCase(BaseTestCase):

    def test_case_insensitive_dict(self):
        test_data = {
            "lower-case-key": uuid.uuid4().hex,
            "UPPER-CASE-KEY": uuid.uuid4().hex,
            "CamelCaseKey": uuid.uuid4().hex}
        cidict = CaseInsensitiveDict(test_data)

        for k, v in test_data.items():
            self.assertTrue(cidict[k], v)

    def test_cookies_from_jar(self):
        test_cookie_jar = cookielib.CookieJar()

        cookies_dict = from_cookiejar(test_cookie_jar)

        for cookie in test_cookie_jar:
            self.assertEquals(cookies_dict[cookie.name], cookie.value)

    def test_jar_from_cookies(self):
        cookies_dict = dict([(uuid.uuid4().hex, uuid.uuid4().hex) for x in xrange(10)])
        cookies_list = [(uuid.uuid4().hex, uuid.uuid4().hex) for x in xrange(10)]

        cookiejar1 = to_cookiejar(cookies_dict)
        cookiejar2 = to_cookiejar(cookies_list)

        for cookie in cookiejar1:
            self.assertEquals(cookie.value, cookies_dict[cookie.name])

        for cookie in cookiejar2:
            for k, v in cookies_list:
                if k == cookie.name:
                    self.assertEquals(cookie.value, v)

    def test_decode_gzip(self):
        from gzip import GzipFile
        try:
            from cString import StringIO
        except ImportError:
            from StringIO import StringIO

        data_for_gzip = Request.__doc__
        tmp_buffer = StringIO()

        gziped_buffer = GzipFile(
            fileobj=tmp_buffer,
            mode="wb",
            compresslevel=7)

        gziped_buffer.write(data_for_gzip)
        gziped_buffer.close()

        gzipped_data = tmp_buffer.getvalue()
        tmp_buffer.close()
        self.assertEquals(data_for_gzip, decode_gzip(gzipped_data))

    def test_morsel_to_cookie(self):
        from time import strftime, localtime
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        m = Morsel()
        m['domain'] = ".yandex"
        m['domain'] = ".yandex.ru"
        m['path'] = "/"
        m['expires'] = "Fri, 27-Aug-2021 17:43:25 GMT"
        m.key = "dj2enbdj3w"
        m.value = "fvjlrwnlkjnf"

        c = morsel_to_cookie(m)
        self.assertEquals(m.key, c.name)
        self.assertEquals(m.value, c.value)
        for x in ('expires', 'path', 'comment', 'domain',
                  'secure', 'version'):
            if x == 'expires':
                self.assertEquals(m[x], strftime(time_template, localtime(getattr(c, x, None))))
            elif x == 'version':
                self.assertTrue(isinstance(getattr(c, x, None), int))
            else:
                self.assertEquals(m[x], getattr(c, x, None))

    def test_data_wrapper(self):
        random_key1 = "key_" + uuid.uuid4().get_hex()[:10]
        random_key2 = "key_" + uuid.uuid4().get_hex()[:10]
        random_key3 = "key_" + uuid.uuid4().get_hex()[:10]
        random_value1 = "value_" + uuid.uuid4().get_hex()
        random_value2 = "value_" + uuid.uuid4().get_hex()
        random_value3 = "value_" + uuid.uuid4().get_hex()

        test_dict = {random_key1: random_value1,
                     random_key2: [random_value1, random_value2],
                     random_key3: (random_value2, random_value3)}
        test_list = ((random_key1, random_value1),
                     (random_key2, [random_value1, random_value2]),
                     (random_key3, (random_value2, random_value3)))

        control_list = ((random_key1, random_value1),
                        (random_key2, random_value1),
                        (random_key2, random_value2),
                        (random_key3, random_value2),
                        (random_key3, random_value3))

        converted_dict = data_wrapper(test_dict)
        for k, v in control_list:
            tmp = []
            for k2, v2 in converted_dict:
                if k2 == k:
                    tmp.append(v2)
            self.assertTrue(v in tmp)

        converted_list = data_wrapper(test_list)
        for k, v in control_list:
            tmp = []
            for k2, v2 in converted_list:
                if k2 == k:
                    tmp.append(v2)
            self.assertTrue(v in tmp)

    def test_curl_post_files(self):
        test_files = (('field_file_name', './README.rst'),
                      ('field_file_name2', open('./setup.py')),
                      ('multiple_files_field', (open("./README.rst"), "./setup.py")))

        curl_files_dict = make_curl_post_files(test_files)

        for k, v in curl_files_dict:
            if isinstance(v, (TupleType, ListType)):
                self.assertTrue(isinstance(v, (TupleType, ListType)))
                self.assertTrue(os.path.exists(v[1]))
                self.assertEquals(v[0], pycurl.FORM_FILE)
            else:
                assert False


class AuthManagersTestCase(BaseTestCase):


    def test_parse_dict_header(self):
        value = '''username="Mufasa",
                 realm="testrealm@host.com",
                 nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                 uri="/dir/index.html",
                 qop=auth,
                 nc=00000001,
                 cnonce="0a4f113b",
                 response="6629fae49393a05397450978507c4ef1",
                 opaque="5ccc069c403ebaf9f0171e9517f40e41"'''

        parsed_header = parse_dict_header(value)
        self.assertEquals(parsed_header['username'], "Mufasa")
        self.assertEquals(parsed_header['realm'], "testrealm@host.com")
        self.assertEquals(parsed_header['nonce'], "dcd98b7102dd2f0e8b11d0f600bfb0c093")
        self.assertEquals(parsed_header['uri'], "/dir/index.html")
        self.assertEquals(parsed_header['qop'], "auth")
        self.assertEquals(parsed_header['nc'], "00000001")


    def test_parse_authorization_header(self):
        test_digest_value = '''Digest username="Mufasa",
        realm="testrealm@host.com",
        nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
        uri="/dir/index.html",
        qop=auth,
        nc=00000001,
        cnonce="0a4f113b",
        response="6629fae49393a05397450978507c4ef1",
        opaque="5ccc069c403ebaf9f0171e9517f40e41"'''

        digest_authorization = parse_authorization_header(test_digest_value)

        control_dict = {'username': 'Mufasa',
                        'nonce': 'dcd98b7102dd2f0e8b11d0f600bfb0c093',
                        'realm': 'testrealm@host.com',
                        'qop': 'auth',
                        'cnonce': '0a4f113b',
                        'nc': '00000001',
                        'opaque': '5ccc069c403ebaf9f0171e9517f40e41',
                        'uri': '/dir/index.html',
                        'response': '6629fae49393a05397450978507c4ef1'}

        for k, v in control_dict.iteritems():
            self.assertEquals(digest_authorization[k], v)

        self.assertTrue(isinstance(digest_authorization, Authorization))

        test_oauth_header_value = '''OAuth realm="Photos",
        oauth_consumer_key="dpf43f3p2l4k3l03",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131200",
        oauth_nonce="wIjqoS",
        oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",
        oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"'''

        oauth_authorization = parse_authorization_header(test_oauth_header_value)

        control_dict = {'realm': 'Photos',
                        'oauth_nonce': 'wIjqoS',
                        'oauth_timestamp': '137131200',
                        'oauth_signature': '74KNZJeDHnMBp0EMJ9ZHt/XKycU=',
                        'oauth_consumer_key': 'dpf43f3p2l4k3l03',
                        'oauth_signature_method': 'HMAC-SHA1',
                        'oauth_callback': 'http://printer.example.com/ready'}


        for k, v in control_dict.iteritems():
            self.assertEquals(oauth_authorization[k], v)

        self.assertTrue(isinstance(digest_authorization, Authorization))


    def test_escape(self):
        self.assertEquals(urllib.unquote(url_escape("http://sp.example.com/")),
                          "http://sp.example.com/")


    def test_parse_authentication_header(self):
        test_digest_authenticate_header = '''Digest
                 realm="testrealm@host.com",
                 qop="auth,auth-int",
                 nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                 opaque="5ccc069c403ebaf9f0171e9517f40e41"'''

        parsed_authentication = parse_authenticate_header(test_digest_authenticate_header)

        control_dict = {'realm': 'testrealm@host.com',
                        'qop': 'auth,auth-int',
                        'nonce': "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                        'opaque': "5ccc069c403ebaf9f0171e9517f40e41"}

        for k, v in control_dict.iteritems():
            self.assertEquals(parsed_authentication[k], v)

        self.assertTrue(isinstance(parsed_authentication, WWWAuthenticate))
        oauth_authentication_header_value = 'OAuth realm="http://sp.example.com/"'

        parsed_oauth_authentication = parse_authenticate_header(oauth_authentication_header_value)

        control_dict = {'realm': 'http://sp.example.com/'}
        for k, v in control_dict.iteritems():
            self.assertEquals(parsed_oauth_authentication[k], v)

        self.assertTrue(isinstance(parsed_oauth_authentication, WWWAuthenticate))


    def test_generate_nonce(self):
        self.assertEquals(len(generate_nonce(8)), 8)

    def test_generate_verifier(self):
        self.assertEquals(len(generate_nonce(8)), 8)

    def test_signature_HMAC_SHA1(self):
        consumer_secret = "consumer_secret"
        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisco,+CA&oauth_signature_method=HMAC-SHA1'

        #url = u'https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-contacts=10'


        request = {'method': 'GET',
                   'normalized_url': normalize_url(url),
                   'normalized_parameters': normalize_parameters(url)}

        control_signature = 'W1dE5qAXk/+9bYYCH8P6ieE2F1I='
        control_base_signature_string = 'GET&http%3A%2F%2Fapi.simplegeo.com%2F1.0%2Fplaces%2Faddress.json&address%3D41%2520Decatur%2520St%252C%2520San%2520Francisco%252C%2520CA%26category%3Danimal%26oauth_signature_method%3DHMAC-SHA1%26q%3Dmonkeys'

        method = SignatureMethod_HMAC_SHA1()
        self.assertEquals(method.signing_base(request, consumer_secret, None)[1], control_base_signature_string)
        self.assertEquals(method.sign(request, consumer_secret, None), control_signature)

        consumer_secret = 'kd94hf93k423kf44'
        token_secret = 'pfkkdhi9sl3r4s00'

        url = 'http://photos.example.net/photos?file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'

        request = {'method': 'GET',
                   'normalized_url': normalize_url(url),
                   'normalized_parameters': normalize_parameters(url)}

        control_signature = 'tR3+Ty81lMeYAr/Fid0kMTYa/WM='
        control_base_signature_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'

        method = SignatureMethod_HMAC_SHA1()
        self.assertEquals(method.signing_base(request, consumer_secret, token_secret)[1], control_base_signature_string)
        self.assertEquals(method.sign(request, consumer_secret, token_secret), control_signature)


    def test_signature_PLAIN_TEXT(self):
        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'

        request = {'method': 'POST',
                   'normalized_url': normalize_url(url),
                   'normalized_parameters': normalize_parameters(url)}

        method = SignatureMethod_PLAINTEXT()

        self.assertEquals(method.sign(request, "djr9rjt0jd78jf88", "jjd999tj88uiths3"), 'djr9rjt0jd78jf88%26jjd999tj88uiths3')
        self.assertEquals(method.sign(request, "djr9rjt0jd78jf88", "jjd99$tj88uiths3"), 'djr9rjt0jd78jf88%26jjd99%2524tj88uiths3')
        self.assertEquals(method.sign(request, "djr9rjt0jd78jf88", None), 'djr9rjt0jd78jf88%26')


    def test_normalize_parameters(self):
        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'
        parameters = 'address=41%20Decatur%20St%2C%20San%20Francisc%E2%9D%A6%2C%20CA&category=animal&q=monkeys'
        self.assertEquals(parameters, normalize_parameters(url))

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\xe2\x9d\xa6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(parameters, normalize_parameters(url))



    def test_normalize_url(self):
        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'
        control_url = "http://api.simplegeo.com/1.0/places/address.json"

        self.assertEquals(control_url, normalize_url(url))

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\xe2\x9d\xa6,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(control_url, normalize_url(url))

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        self.assertEquals(control_url, normalize_url(url))


    def test_oauth_consumer(self):
        consumer_key = "ljdsfhwjkbnflkjfqkebr"
        consumer_secret = "kjwbefpbnwefgwre"
        consumer = OAuthConsumer(consumer_key, consumer_secret)
        self.assertEquals(consumer_key, consumer._key)
        self.assertEquals(consumer_secret, consumer._secret)
        self.assertTrue(isinstance(consumer, OAuthConsumer))

    def test_oauth_token(self):
        token_key = "lfsjdafjnrbeflbwreferf"
        token_secret = "fjrenlwkjbferlwerjuhiuyg"
        token = OAuthToken(token_key, token_secret)
        self.assertTrue(isinstance(token, OAuthToken))


    def test_oauth_PLAINTEXT(self):
        consumer_key = "be4b2eab12130803"
        consumer_secret = "a2e0e39b27d08ee2f50c4d3ec06f"

        token_key = "lfsjdafjnrbeflbwreferf"
        token_secret = "fjrenlwkjbferlwerjuhiuyg"

        tmp_token_key = "kfwbehlfbqlihrbwf"
        tmp_token_secret = "dlewknfd3jkr4nbfklb5ihrlbfg"

        verifier = ''.join(map(str, [randint(1, 40) for x in xrange(7)]))

        request_token_url = "http://h.wrttn.me/oauth/1.0/request_token/%s/%s/%s/%s" % \
                             (consumer_key, consumer_secret, tmp_token_key, tmp_token_secret)


        authorize_url = "http://h.wrttn.me/oauth/1.0/authorize/%s" % verifier
        access_token_url = "http://h.wrttn.me/oauth/1.0/access_token/%s/%s/%s/%s/%s/%s/%s" % \
                           (consumer_key, consumer_secret,
                            tmp_token_key, tmp_token_secret,
                            verifier, token_key, token_secret)

        protected_resource = "http://h.wrttn.me/oauth/1.0/protected_resource/%s/%s" % (consumer_secret, token_secret)

        r = Request("GET", protected_resource,
                    debug=stdout_debug
                    )

        consumer = OAuthConsumer(consumer_key, consumer_secret)

        self.assertRaises(RuntimeError, OAuthManager, consumer)
        oauth_manager = OAuthManager(consumer, request_token_url=request_token_url,
                                     authorize_url=authorize_url,
                                     access_token_url=access_token_url,
                                     signature_method=SignatureMethod_PLAINTEXT)

        self.assertEquals(oauth_manager.state, 1)
        self.assertTrue(isinstance(oauth_manager._signature_method, SignatureMethod))
        oauth_manager.setup_request(r)

        #self.assertEquals(oauth_manager._debug, stdout_debug)

        oauth_manager.request_token()

        self.assertEquals(oauth_manager.state, 3)
        self.assertEquals(oauth_manager._tmp_token_key, tmp_token_key)
        self.assertEquals(oauth_manager._tmp_token_secret, tmp_token_secret)

        self.assertEquals(oauth_manager.confirm_url, "%s?oauth_token=%s" % \
                          (oauth_manager._authorize_url, oauth_manager._tmp_token_key))

        pin = json.loads(requests.get(oauth_manager.confirm_url,
                                           debug=stdout_debug).content)['verifier']
        oauth_manager.verify(pin)


        self.assertEquals(oauth_manager.state, 5)
        self.assertEquals(pin, oauth_manager._verifier)
        self.assertEquals(tmp_token_key, oauth_manager._tmp_token_key)
        self.assertEquals(tmp_token_secret, oauth_manager._tmp_token_secret)

        oauth_manager.access_request()

        self.assertTrue(isinstance(oauth_manager._token, OAuthToken))
        self.assertEquals(oauth_manager._token._key, token_key)
        self.assertEquals(oauth_manager._token._secret, token_secret)
        self.assertEquals(oauth_manager.state, 7)

        ## opener, body_output, headers_output = r.build_opener(r._build_url())
        ## oauth_manager.setup(opener)
        ## opener.perform()
        ## response = Response(url=r._build_url(), curl_opener=opener,
        ##                      body_output=body_output,
        ##                      headers_output=headers_output, request=r,
        ##                      cookies=r._cookies)
        ## self.assertEquals(response.status_code, 200)
        ## self.assertEquals(json.loads(response.content)['success'], True)


    def test_oauth_HMAC_SHA1(self):
        consumer_key = "be4b2eab12130803"
        consumer_secret = "a2e0e39b27d08ee2f50c4d3ec06f"

        token_key = "lfsjdafjnrbeflbwreferf"
        token_secret = "fjrenlwkjbferlwerjuhiuyg"

        tmp_token_key = "kfwbehlfbqlihrbwf"
        tmp_token_secret = "dlewknfd3jkr4nbfklb5ihrlbfg"

        verifier = ''.join(map(str, [randint(1, 40) for x in xrange(7)]))

        request_token_url = "http://h.wrttn.me/oauth/1.0/request_token/%s/%s/%s/%s" % \
                             (consumer_key, consumer_secret, tmp_token_key, tmp_token_secret)


        authorize_url = "http://h.wrttn.me/oauth/1.0/authorize/%s" % verifier
        access_token_url = "http://h.wrttn.me/oauth/1.0/access_token/%s/%s/%s/%s/%s/%s/%s" % \
                           (consumer_key, consumer_secret,
                            tmp_token_key, tmp_token_secret,
                            verifier, token_key, token_secret)

        protected_resource = "http://h.wrttn.me/oauth/1.0/protected_resource/%s/%s" % (consumer_secret, token_secret)

        r = Request("GET", protected_resource,
                    debug=stdout_debug,
                    headers = (("Test-header", "test-value"), )
                    )

        consumer = OAuthConsumer(consumer_key, consumer_secret)

        self.assertRaises(RuntimeError, OAuthManager, consumer)
        oauth_manager = OAuthManager(consumer, request_token_url=request_token_url,
                                     authorize_url=authorize_url,
                                     access_token_url=access_token_url,
                                     signature_method=SignatureMethod_HMAC_SHA1)

        self.assertEquals(oauth_manager.state, 1)
        self.assertTrue(isinstance(oauth_manager._signature_method, SignatureMethod))
        oauth_manager.setup_request(r)

#        self.assertEquals(oauth_manager._debug, stdout_debug)

        oauth_manager.request_token()

        self.assertEquals(oauth_manager.state, 3)
        self.assertEquals(oauth_manager._tmp_token_key, tmp_token_key)
        self.assertEquals(oauth_manager._tmp_token_secret, tmp_token_secret)

        self.assertEquals(oauth_manager.confirm_url, "%s?oauth_token=%s" % \
                          (oauth_manager._authorize_url, oauth_manager._tmp_token_key))

        pin = json.loads(requests.get(oauth_manager.confirm_url,
                                           debug=stdout_debug).content)['verifier']
        oauth_manager.verify(pin)


        self.assertEquals(oauth_manager.state, 5)
        self.assertEquals(pin, oauth_manager._verifier)
        self.assertEquals(tmp_token_key, oauth_manager._tmp_token_key)
        self.assertEquals(tmp_token_secret, oauth_manager._tmp_token_secret)

        oauth_manager.access_request()

        self.assertTrue(isinstance(oauth_manager._token, OAuthToken))
        self.assertEquals(oauth_manager._token._key, token_key)
        self.assertEquals(oauth_manager._token._secret, token_secret)
        self.assertEquals(oauth_manager.state, 7)
        ## opener, body_output, headers_output = r.build_opener(r._build_url())
        ## oauth_manager.setup(opener)
        ## opener.perform()
        ## response = Response(url=r._build_url(), curl_opener=opener,
        ##                      body_output=body_output,
        ##                      headers_output=headers_output, request=r,
        ##                      cookies=r._cookies)
        ## self.assertEquals(response.status_code, 200)
        ## self.assertEquals(json.loads(response.content)['success'], True)


    def test_3_legged_oauth(self):
        consumer_key = "be4b2eab12130803"
        consumer_secret = "a2e0e39b27d08ee2f50c4d3ec06f"

        token_key = "lfsjdafjnrbeflbwreferf"
        token_secret = "fjrenlwkjbferlwerjuhiuyg"

        tmp_token_key = "kfwbehlfbqlihrbwf"
        tmp_token_secret = "dlewknfd3jkr4nbfklb5ihrlbfg"

        verifier = ''.join(map(str, [randint(1, 40) for x in xrange(7)]))

        request_token_url = "http://h.wrttn.me/oauth/1.0/request_token/%s/%s/%s/%s" % \
                             (consumer_key, consumer_secret, tmp_token_key, tmp_token_secret)


        authorize_url = "http://h.wrttn.me/oauth/1.0/authorize/%s" % verifier
        access_token_url = "http://h.wrttn.me/oauth/1.0/access_token/%s/%s/%s/%s/%s/%s/%s" % \
                           (consumer_key, consumer_secret,
                            tmp_token_key, tmp_token_secret,
                            verifier, token_key, token_secret)

        protected_resource = "http://h.wrttn.me/oauth/1.0/protected_resource/%s/%s" % (consumer_secret, token_secret)


        consumer = OAuthConsumer(consumer_key, consumer_secret)
        token = OAuthToken(token_key, token_secret)

        oauth_manager = OAuthManager(consumer, token=token,
                                     signature_method=SignatureMethod_HMAC_SHA1)

        r = requests.get(protected_resource,
                         debug=stdout_debug,
                         auth=oauth_manager
                         )

        self.assertEquals(oauth_manager.state, 7)
        self.assertTrue(isinstance(oauth_manager._signature_method, SignatureMethod_HMAC_SHA1))

#        self.assertEquals(oauth_manager._debug, stdout_debug)
        self.assertEquals(r.status_code, 200)
        self.assertEquals(json.loads(r.content)['success'], True)



class AsyncTestCase(BaseTestCase):


    def success_callback(self, async_client, opener, response, **kwargs):
        self.assertTrue(isinstance(opener.request, Request))
        self.assertTrue(isinstance(response, Response))
        self.assertTrue(isinstance(async_client, AsyncClient))
        self.assertTrue(async_client._default_user_agent in response.content)

    def fail_callback(self, async_client, opener, errno, errmsg, **kwargs):
        self.assertTrue(isinstance(async_client, AsyncClient))

    def test_AsyncClient_core(self):
        async_client = AsyncClient(size=20)

        self.assertEquals(async_client._num_conn, 20)
        self.assertEquals(async_client._remaining, 0)
        self.assertEquals(async_client.success_callback, None)
        self.assertEquals(async_client.fail_callback, None)
        self.assertEquals(async_client._openers_pool, None)
        self.assertEquals(async_client._data_queue, [])
        self.assertEquals(async_client.connections_count, 0)

        async_client.add_handler(url=build_url("/get"),
                                 method="get",
                                 params={"get1": "get1 value",
                                         "get2": "get2 value"},
                                 success_callback=self.success_callback,
                                 fail_callback=self.fail_callback)
        self.assertEquals(len(async_client._data_queue), 1)
        self.assertTrue(isinstance(async_client._data_queue[0], dict))

        params = self.random_dict(10)

        async_client.get(url=build_url("/get"), params=params,
                         success_callback=self.success_callback,
                         fail_callback=self.fail_callback)
        self.assertTrue(isinstance(async_client._data_queue[1], dict))
        self.assertEquals(async_client._data_queue[1]['params'], params)
        self.assertEquals(async_client.connections_count, 2)

    def test_async_get(self):
        async_client_global = AsyncClient(success_callback=self.success_callback,
                                          fail_callback=self.fail_callback)

        params = self.random_dict(10)
        url = build_url("get")

        self.assertEquals(async_client_global.get(url, params=params), async_client_global)
        self.assertEquals(len(async_client_global._data_queue), 1)

        # Test process_func
        def process_func(num_processed, remaining, num_urls,
                         success_len, error_len):
            print("\nProcess {0} {1} {2} {3} {4}".format(num_processed, remaining, num_urls,
                                                         success_len, error_len))
            self.assertEquals(num_urls, 2)

        def fail_callback(request, errno, errmsg, async_client, opener):
            self.assertTrue(isinstance(request, Request))
            self.assertTrue(isinstance(async_client, AsyncClient))
            self.assertEquals(async_client, async_client_global)
            self.assertEquals(errno, 6)
            self.assertEquals(errmsg, "Couldn't resolve host '{0}'".format(request.url[7:]))
        async_client_global.get("http://fwbefrubfbrfybghbfb4gbyvrv.com", params=params,
                                fail_callback=fail_callback)
        self.assertEquals(len(async_client_global._data_queue), 2)
        async_client_global.start(process_func)


    def test_setup_opener(self):
        async_client = AsyncClient()

        data = self.random_dict(10)
        data['url'] = build_url("get")
        data['method'] = 'get'
        opener = async_client.get_opener()

        self.assertEquals(getattr(opener, 'success_callback', None), None)
        self.assertEquals(getattr(opener, 'fail_callback', None), None)
        self.assertEquals(getattr(opener, 'request', None), None)

        data['success_callback'] = lambda **kwargs: kwargs
        data['fail_callback'] = lambda **kwargs: kwargs

        async_client.configure_opener(opener, data)
        self.assertTrue(isinstance(opener.request, Request))
        self.assertTrue(isinstance(opener.success_callback, FunctionType))
        self.assertTrue(isinstance(opener.fail_callback, FunctionType))


    def test_add_handler(self):
        async_client = AsyncClient()
        data = self.request_params()


        self.assertRaises(InterfaceError, async_client.add_handler, **data)

        data['success_callback'] = lambda **kwargs: kwargs
        data['fail_callback'] = lambda **kwargs: kwargs

        async_client.add_handler(**data)
        self.assertEquals(async_client._data_queue[0], data)
        self.assertEquals(async_client._num_urls, 1)
        self.assertEquals(async_client._remaining, 1)

    def test_get_opener(self):
        async_client = AsyncClient()
        opener = async_client.get_opener()
        self.assertEquals(opener.fp, None)
        self.assertNotEqual(opener, None)


    def test_AsyncClient_contextmanager(self):
        with AsyncClient(success_callback=self.success_callback,
                         fail_callback=self.fail_callback) as async_client_global:

            params = self.random_dict(10)
            url = build_url("get")

            self.assertEquals(async_client_global.get(url, params=params), async_client_global)
            self.assertEquals(len(async_client_global._data_queue), 1)

            # Test process_func
            def process_func(num_processed, remaining, num_urls,
                             success_len, error_len):
                print("\nProcess {0} {1} {2} {3} {4}".format(num_processed, remaining, num_urls,
                                                             success_len, error_len))
                self.assertEquals(num_urls, 2)

            def fail_callback(request, errno, errmsg, async_client, opener):
                self.assertTrue(isinstance(request, Request))
                self.assertTrue(isinstance(async_client, AsyncClient))
                self.assertEquals(async_client, async_client_global)
                self.assertEquals(errno, 6)
                self.assertEquals(errmsg, "Couldn't resolve host '{0}'".format(request.url[7:]))
            async_client_global.get("http://fwbefrubfbrfybghbfb4gbyvrv.com", params=params,
                                    fail_callback=fail_callback)
            self.assertEquals(len(async_client_global._data_queue), 2)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RequestsTestCase))
    suite.addTest(unittest.makeSuite(ResponseTestCase))
    suite.addTest(unittest.makeSuite(RequestTestCase))
    suite.addTest(unittest.makeSuite(UtilsTestCase))
    suite.addTest(unittest.makeSuite(AuthManagersTestCase))
    suite.addTest(unittest.makeSuite(AsyncTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="suite")
