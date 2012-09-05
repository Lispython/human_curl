#!/usr/bin/env python
# -*- coding:  utf-8 -*-

from urlparse import urljoin

from human_curl import async, Response

HTTP_TEST_URL = "http://h.wrttn.me"
def build_url(*parts):
    return urljoin(HTTP_TEST_URL, "/".join(parts))

urls = [build_url("get?test_key=%s" % str(x)) for x in xrange(10)]

print(urls)

def test_result(result):
    print(" ---> ", isinstance(result, Response))

for url in urls:
    async.get(urls[0])

async.start(callback=test_result)


# GRequests compatible code

from human_curl import async

urls = [
    'http://www.heroku.com',
    'http://tablib.org',
    'http://httpbin.org',
    'http://python-requests.org',
    'http://kennethreitz.com'
    'http://wrttn.me'
]

rs1 = [async.get(u) for u in urls]

print async.map(rs1)

rs2 = [async.get(u) for u in urls]

def success_callback(request, response):
    print(request, response)

print async.map(rs1, on_success=success_callback, on_fail=fail_callback)

