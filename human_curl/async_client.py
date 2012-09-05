"""
human_curl.async
~~~~~

Async module

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import pycurl
import methods
from .core import Request
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


def async_map(urls, callback=None, size=None):
    async_client = AsyncClient(size=size)
    for url in urls:
        pass


class AsyncClient(object):
    def __init__(self, size=None):
        self._requests = {}
        self._responses = {}

        self._urls_count = None
        self._urls_mapping = {}
        self._handlers = []
        self._multi_curl = pycurl.CurlMulti()

    def add_handler(self, handler):

        self._handlers.append(handler)

    def get(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def put(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def head(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def delete(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def post(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def options(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def method(self, url, callback=None, **kwargs):
        return patched(methods.get)(url, callback=None, **kwargs)

    def __getattribute__(self, name):
        print("__getattribute__ %s" % name)
        if name.upper() in Request.SUPPORTED_METHODS:
            self._urls_count += 1
        return object.__getattribute__(self, name)

    def start(self, callback=None):

        while num_processed < num_urls:
            # Run the internal curl state machine for the multi stack
            while 1:
                ret, num_handles = self._multi_curl.perform()
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break

            # Check for curl objects which have terminated, and add them to the freelist
            while 1:
                num_q, ok_list, err_list = self._multi_curl.info_read()

                for c in ok_list:
                    c.fp.close()
                    c.fp = None
                    self._multi_curl.remove_handle(c)
                    print "Success:", c.filename, c.url, c.getinfo(pycurl.EFFECTIVE_URL)

                for c, errno, errmsg in err_list:
                    c.fp.close()
                    c.fp = None
                    self._multi_curl.remove_handle(c)
                    print "Failed: ", c.filename, c.url, errno, errmsg
                if num_q == 0:
                    break

            # Currently no more I/O is pending, could do something in the meantime
            # (display a progress bar, etc.).
            # We just call select() to sleep until some more data is available.
            self._multi_curl.select(1.0)



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
