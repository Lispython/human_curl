#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.tests
~~~~~~~~~~~~~~~~~~~~~~~~~~

Unittests for human_curl

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""
from __future__ import with_statement

import os
import time
import pycurl
import cookielib
from Cookie import Morsel
import json
import uuid
import logging
from urlparse import urljoin
import unittest
from types import TupleType, StringTypes, ListType
from urllib import urlencode
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import human_curl as requests
from human_curl import Request, Response
from human_curl.auth import BasicAuth, DigestAuth
from human_curl.utils import (from_cookiejar, decode_gzip, CaseInsensitiveDict,
                              to_cookiejar, morsel_to_cookie, data_wrapper,
                              make_curl_post_files)

from human_curl.exceptions import CurlError, InterfaceError, InvalidMethod

logger = logging.getLogger("human_curl")

TEST_METHODS = (
    ('get', requests.get),
    ('post', requests.post),
    ('head', requests.head),
    ('delete', requests.delete),
    ('put', requests.put),
    ('options', requests.options))

# Use https://github.com/Lispython/httphq
HTTP_TEST_URL = "http://h.wrttn.me"
HTTPS_TEST_URL = "https://h.wrttn.me"


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


class RequestsTestCase(unittest.TestCase):

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


class ResponseTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class RequestTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass


class UtilsTestCase(unittest.TestCase):

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


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RequestsTestCase))
    suite.addTest(unittest.makeSuite(ResponseTestCase))
    suite.addTest(unittest.makeSuite(RequestTestCase))
    suite.addTest(unittest.makeSuite(UtilsTestCase))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest="suite")
