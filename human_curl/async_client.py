"""
human_curl.async
~~~~~

Async module

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import methods
## import ioloop

## def handle_request(response):
##     if response.error:
##         print "Error:", response.error
##     else:
##         print response.body
##     ioloop.IOLoop.instance().stop()

## http_client = httpclient.AsyncHTTPClient()
## http_client.fetch("http://www.google.com/", handle_request)
## ioloop.IOLoop.instance().start()


def async_map(urls, callback):
    async_client = AsyncClient()
    for url in urls:
        pass


class AsyncClient(object):
    def __init__(self, io_loop=None):
        self._requests = {}
        self._responses = {}

        self._ioloop = None

    def get(self, url, callback=None): pass
    def put(self, url, callback=None): pass
    def head(self, url, callback=None): pass
    def delete(self, url, callback=None): pass
    def post(self, url, callback=None): pass
    def options(self, url, callback=None): pass
    def method(self, url, callback=None): pass

    def  start(self):
        self._ioloop.IOLoop.instance().start()



def patched(f):
    """Patches a given API function to not send.
    """

    def wrapped(*args, **kwargs):
        kwargs['return_response'] = False
        return f(*args, **kwargs)
    return wrapped


get = patched(methods.get)
put = patched(methods.put)
head = patched(methods.head)
delete = patched(methods.delete)
post = patched(methods.post)
options = patched(methods.options)


## def get(url, **kwargs): pass
## def put(url, **kwargs): pass
## def head(url, **kwargs): pass
## def delete(url, **kwargs): pass
## def post(url, **kwargs): pass
## def options(url, **kwargs): pass
