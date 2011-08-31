#!/usr/bin/env python
# -*- coding:  utf-8 -*-
"""
human_curl.debug
~~~~~~~~~~~~~~~~~~~~~~~~~~

Debuggging tests for human_curl

:copyright: (c) 2011 by Alexandr Lispython (alex@obout.ru).
:license: BSD, see LICENSE for more details.
"""

import logging
from .tests import *


logger = logging.getLogger("human_curl")
logger.setLevel(logging.DEBUG)

# Add the log message handler to the logger
# LOG_FILENAME = os.path.join(os.path.dirname(__file__), "debug.log")
# handler = logging.handlers.FileHandler(LOG_FILENAME)
handler = logging.StreamHandler()

formatter = logging.Formatter("%(levelname)s %(asctime)s %(module)s [%(lineno)d] %(process)d %(thread)d | %(message)s ")

handler.setFormatter(formatter)

logger.addHandler(handler)
