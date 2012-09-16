"""
human_curl.compat
~~~~~~~~~~~~~~~~~

Compatibility module

:copyright: (c) 2012 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""


try:
    import simplejson as json
except ImportError:
    import json
