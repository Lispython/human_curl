#!/usr/bin/env python
# -*- coding:  utf-8 -*-
import time
import human_curl
import requests
import json
import uuid
from pprint import pprint
from contextlib import contextmanager

@contextmanager
def timer(func):
    print("Start test %s" % func)
    t = time.time()
    yield
    print("Total time %s for %s --------------- "% (str(time.time()-t), func))


# TEST REDIRECTS
with timer("human_curl"):
    r = human_curl.get('http://httpbin.org/redirect/7', allow_redirects=True,
                       max_redirects=10)
    print(r)
    print(len(r.history))


with timer("python-requests"):
    r = requests.get('http://httpbin.org/redirect/7', allow_redirects=True)
    print(r)
    print(len(r.history))


files =  {
    #('first_file', open("/tmp/testfile1.txt.gz")),
    'first_file': open("/tmp/testfile2.txt"),
    'second_file': open("/tmp/testfile3.txt"),
    }

#FILES UPLOADING
with timer("human_curl"):
    try:
        r = human_curl.post('http://h.wrttn.me/post', allow_redirects=True, files=files,
                            max_redirects=10)
        print(r)
        #print(json.loads(r.content))
    except Exception, e:
        print(e)

with timer("python-requests"):
    try:
        r = requests.post('http://h.wrttn.me/post', allow_redirects=True, files=files)
        print(r)
        #print(json.loads(r.response))
    except Exception, e:
        print(e)

custom_headers = (
    ('Test-Header', 'fwkjenwkljbnfkjqnewfrjven3lrf'),
    ('Another-Header', 'ifenwqnfe;wnfqfjlweqnnlf')
    )

with timer("human_curl"):
    r = human_curl.get("http://h.wrttn.me/headers",
                        headers=custom_headers)
    print(r)
    print(json.loads(r.content))

custom_vars = {
    uuid.uuid4().hex: uuid.uuid4().hex,
    uuid.uuid4().hex: uuid.uuid4().hex,
    uuid.uuid4().hex: uuid.uuid4().hex,
    }

with timer('human_curl'):
    r =  human_curl.post("http://h.wrttn.me/post",
                        data = custom_vars, debug=True)
    print(r)
    print(json.loads(r.content))

