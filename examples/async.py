#!/usr/bin/env python
# -*- coding:  utf-8 -*-

from urlparse import urljoin

from human_curl import async, Response, async_client

HTTP_TEST_URL = "http://h.wrttn.me"
def build_url(*parts):
    return urljoin(HTTP_TEST_URL, "/".join(parts))

urls = [build_url("get?test_key=%s" % str(x)) for x in xrange(10)]

rs = [async_client.get(url) for url in urls]
async_client.start()

print(async_client.responses)
