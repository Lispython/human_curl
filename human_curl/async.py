"""
human_curl.async
~~~~~~~~~~~~~~~~

Async module

:copyright: (c) 2011 - 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

from logging import getLogger
from types import FunctionType

try:
    import pycurl2 as pycurl
except ImportError:
    import pycurl

# Lib imports
from . import get_version
from .core import Request
from .exceptions import InterfaceError, CurlError


__all__ = ("AsyncClient", "map", "async_client", "get", "head", "post", "put", "options", "delete")

logger = getLogger('human_curl.async')

DEFAULT_MAX_OPENERS = 1000
DEFAULT_SLEEP_TIMEOUT = 2.0
DEFAULT_INFO_READ_RETRIES_MAX = 10


class AsyncClient(object):
    """Client to create async requests

    .. versionadded:: 0.0.5

    """

    def __init__(self, size=DEFAULT_MAX_OPENERS,
                 success_callback=None, fail_callback=None,
                 sleep_timeout=DEFAULT_SLEEP_TIMEOUT,
                 info_read_retries_max=DEFAULT_INFO_READ_RETRIES_MAX, **kwargs):
        """Create `AsyncClient`

        :param size: openers count
        :param success_callback: default success cullback function
        :param fail_callback: default fail callback function
        :param sleep_timeout: sleep in perform
        :param \*\*kwargs: global request parameters
        """

        self.success_callback = success_callback
        self.fail_callback = fail_callback

        self._remaining = 0
        self._openers_pool = None
        self._num_conn = size
        self._data_queue = []
        self._num_urls = 0
        self._sleep_timeout = sleep_timeout
        self.num_processed = 0
        self._process_func = None
        self._free_openers = []
        self.responses = []
        self._default_user_agent = None
        self._default_params = kwargs
        self._finished = False


    @property
    def user_agent(self):
        """Setup user agent
        """
        if not self._default_user_agent:
            self._default_user_agent = "Mozilla/5.0 (compatible; human_curl.async; {0}; +http://h.wrttn.me/human_curl)".format(get_version())
        return self._default_user_agent


    def add_handler(self, **params):
        """Add request params to data queue

        :param \*\*kwargs: Optional arguments that passed to `Request`.
        """

        # Check callback functions
        if ('success_callback' not in params and not self.success_callback) or \
           ('fail_callback' not in params and not self.fail_callback):
            raise InterfaceError("You must specify success_calback or fail_callback")

        self._data_queue.append(params)
        self._remaining += 1
        self._num_urls = self._remaining

    @property
    def connections_count(self):
        """Calculace and return number of connections

        :return: number of connections
        """
        return min(self._num_conn, self._remaining)

    def build_pool(self):
        """Make openers pool

        :return: returns a new :class:`pycurl.MultiCUrl` object.
        """
        self._openers_pool = pycurl.CurlMulti()
        self._openers_pool.handles = []

        # Get calculated connections count
        num_openers = self.connections_count

        for i in xrange(num_openers):
            self._openers_pool.handles.append(self.get_opener())

        logger.info("Created {0} openers".format(num_openers))
        return self._openers_pool

    @staticmethod
    def get_opener():
        """Make `pycurl.Curl` objcet

        :return opener: :class:`pycurl.Curl` object
        """
        opener = pycurl.Curl()
        opener.fp = None
        opener.setopt(pycurl.NOSIGNAL, 1)
        opener.dirty = False
        return opener

    def perform_pool(self):
        """Perform openers in pool
        """
        while True:
            ret, num_handles = self._openers_pool.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break

    def start(self, process_func=None):
        """Start workers poll

        :param process_func: function to call in process
        """

        if process_func and not isinstance(process_func, FunctionType):
            self._process_func = process_func
            raise InterfaceError("process_func must be function")

        if not self._openers_pool:
            self._openers_pool = self.build_pool()

        self._free_openers = self._openers_pool.handles[:]

        while self._remaining:

            self.process_raw_data()
            self.perform_pool()
            self.process_pending_requests()

            logger.info("Processed {0} from {1} items".format(
                self.num_processed, self._num_urls))

            # Sleep timeout
            self._openers_pool.select(self._sleep_timeout)

        self.cleanup_pool()

    def configure_opener(self, opener, data):
        """Make and configure `Request` from data

        :param opener: :class:`pycurl.Curl` instance
        :param data: `Request` params as dict
        """
        opener = self.reset_opener(opener)

        if 'user_agent' not in data:
            data['user_agent'] = self.user_agent

        mixed_data = self._default_params
        mixed_data.update(data)
        data = mixed_data

        request = Request(**data)
        request.build_opener(data['url'], opener)

        # Reset opener settings to defaults
        opener.request = request
        opener.success_callback = data.pop('success_callback', None) or \
                                  self.success_callback
        opener.fail_callback = data.get('fail_callback', None) or \
                               self.fail_callback
        return opener

    def reset_opener(self, opener):
        """Reset opener settings to defaults

        :param opener: :class:`pycurl.Curl` object
        """
        opener.success_callback = None
        opener.fail_callback = None
        opener.request = None

        if getattr(opener, "dirty", False) is True:
            # After appling this method curl raise error
            # Unable to fetch curl handle from curl object
            opener.reset()

        # Maybe need delete cookies?
        return opener

    def make_response(self, opener):
        """Make response from successed request

        :param opener: :class:`pycurl.Curl` object
        :return response: :class:`Response` object
        """
        response = opener.request.make_response()
        return response

    def process_raw_data(self):
        """Load data from queue, make request instance and add handler
        """

        while self._data_queue and self._free_openers:
            request_data = self._data_queue.pop()
            opener = self._free_openers.pop()

            # Create request object
            self.configure_opener(opener, request_data)

            # Add configured opener to handles pool
            self._openers_pool.add_handle(opener)

    def process_pending_requests(self):
        """Process any requests that were completed by the last
        call to multi.socket_action.
        """
        while True:
            try:
                num_queued, success_list, error_list = self._openers_pool.info_read()
            except Exception, e:
                logger.warn(e)
                raise CurlError(e[0], e[1])

            for opener in success_list:
                opener.fp = None
                self._openers_pool.remove_handle(opener)

                # Make `Response` object from opener
                response = self.make_response(opener)
                opener.success_callback(response=response,
                                        async_client=self, opener=opener)
                ## FIXME: after pycurl.MultiCurl reset error
                ## opener.dirty = True
                self._free_openers.append(opener)

            for opener, errno, errmsg in error_list:
                opener.fp = None
                self._openers_pool.remove_handle(opener)

                opener.fail_callback(errno=errno, errmsg=errmsg,
                                     async_client=self, opener=opener,
                                     request=opener.request)
                ## FIXME: after pycurl.MultiCurl reset error
                ## opener.dirty = True
                self._free_openers.append(opener)


            success_len = len(success_list)
            error_len = len(error_list)

            self.num_processed = self.num_processed + success_len + error_len
            self._remaining -= success_len + error_len

            if self._process_func:
                self._process_func(num_processed=self.num_processed, remaining=self._remaining,
                                  num_urls=self._num_urls, success_len=success_len,
                                  error_len=error_len)

            if num_queued == 0:
                break

    def cleanup_pool(self):
        """Close all fp, clean objects

        :param openers_pool:
        """
        if not self._openers_pool:
            return None

        for opener in self._openers_pool.handles:
            if opener.fp is not None:
                opener.fp.close()
                opener.fp = None
            opener.close()

        self._openers_pool.close()

    def method(self, method, **kwargs):
        """Added request params to data_queue

        :param method: request method
        :return self: :class:`AsyncClient` object
        """
        if 'url' not in kwargs:
            raise InterfaceError("You need specify url param")

        self.add_handler(method=method, **kwargs)

        # Return self to make chain calls
        return self

    def get(self, url, **kwargs):
        return self.method("get", url=url, **kwargs)

    def post(self, url, data='', **kwargs):
        return self.medhod("post", **kwargs)

    def head(self, url, **kwargs):
        return self.method("head", url=url, **kwargs)

    def options(self, url, **kwargs):
        return self.method("options", url, **kwargs)

    def put(self, url, **kwargs):
        return self.method("put", url=url, **kwargs)

    def delete(self, url, **kwargs):
        return self.method("delete", url=url, **kwargs)

    def __del__(self):
        """ Close deascriptors after object delete
        """
        self.cleanup_pool()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        logger.debug((exc_type, exc_value, traceback))
        self.start()


def default_success_callback(response, async_client, opener, **kwargs):
    """Default callback for collect `Response` objects

    :param response: :class:`Response` object
    :param async_client: :class:`AsyncClient` object
    :param opener: :class:`pycurl.Curl` object
    """

    async_client.responses.append(response)

def default_fail_callback(request, errno, errmsg, async_client, opener):
    """Default callback for collect fails

    :param request: :class:`Request` object
    :param errno: error number code
    :param errmsg: error message
    :param async_client: :class:`AsyncClient` object
    :param opener: :class:`pycurl.Curl` object
    """

async_client = AsyncClient(success_callback=default_success_callback,
                           fail_callback=default_fail_callback)


def map(requests):
    """
    :param requests: iterate methods
    """
    if not requests:
        return []
    requests = [request for request in requests]
    async_client.start()
    return async_client.responses


# Make aliases
get = async_client.get
put = async_client.put
post = async_client.post
delete = async_client.delete
head = async_client.head
options = async_client.options
