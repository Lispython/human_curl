#!/usr/bin/env python
# -*- coding:  utf-8 -*-


from tornad.ioloop import IOloop
from human_curl import async
from human_curl import Response

urls = ["http://habrahabr.ru", "http://obout.tu", "http://h.wrttn.me"]

def test_async_result(result):
    assert isinstance(result, Response), True

for url in urls:
    async.get(urls[0])
async.fetch()
