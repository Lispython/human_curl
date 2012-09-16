#!/usr/bin/env python
# -*- coding:  utf-8 -*-

from urlparse import urljoin
from datetime import datetime

from human_curl.async import AsyncClient
from human_curl.utils import stdout_debug

def success_callback(response, **kwargs):
    """This function call when response successed
    """
    print("success callback")
    print(response, response.request)
    print(response.headers)
    print(response.content)
    print(kwargs)

def fail_callback(request, opener, **kwargs):
    """Collect errors
    """
    print("fail callback")
    print(request, opener)
    print(kwargs)


# In kwargs we can pass default arguments
# Add pre and post callback call hooks
async_client = AsyncClient(success_callback=success_callback,
                           fail_callback=fail_callback)

results = []
fails = []

async_client.get('http://h.wrttn.me/get')
async_client.get('http://httpbin.org/get',
                 success_callback=success_callback, fail_callback=fail_callback)

async_client.start()
