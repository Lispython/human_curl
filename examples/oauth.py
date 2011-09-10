#!/usr/bin/env python
# -*- coding:  utf-8 -*-

import human_curl as hurl
from human_curl.auth import BasicAuth, DigestAuth, OAuthManager, OAuthConsumer, OAuthToken

def stdout_debug(debug_type, debug_msg):
    """Print messages
    """
    debug_types = ('I', '<', '>', '<', '>')
    if debug_type == 0:
        print('%s' % debug_msg.strip())
    elif debug_type in (1, 2):
        for line in debug_msg.splitlines():
            print('%s %s' % (debug_types[debug_type], line))
    elif debug_type == 4:
        print('%s %r' % (debug_types[debug_type], debug_msg))


CONSUMER_KEY = ""
CONSUMER_SECRET = ""

REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize"
ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
CALLBACK_URL = "http://h.wrttn.me/request_callback"

ACCESS_TOKEN = ""
ACCESS_TOKEN_SECRET = ""


PROTECTED_RESOURCE = "https://api.twitter.com/1/statuses/home_timeline.json?count=5"

consumer = OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
token = OAuthToken(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)

oauth = OAuthManager(consumer, token)

r = hurl.get(PROTECTED_RESOURCE,
              debug=stdout_debug,
             allow_redirects=False,
             auth=oauth)
print(r)
print(r.content)

