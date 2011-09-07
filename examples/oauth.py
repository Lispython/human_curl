#!/usr/bin/env python
# -*- coding:  utf-8 -*-

import human_curl as hurl
from human_curl.auth import BasicAuth, DigestAuth, OAuth

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

oauth = OAuth((CONSUMER_KEY, CONSUMER_SECRET))


r = hurl.get("https://api.twitter.com/oauth/request_token",
              debug=stdout_debug, allow_redirects=False,
              auth=oauth, headers = {'test_header': 'test_value'})
print(r)


# http://oauth-sandbox.sevengoslings.net/

# Key: caf5ce79d5ec6465
# Secret: 5c16b67f5add6bd1a76e8332da69

## request_token_url = "http://oauth-sandbox.sevengoslings.net/request_token"
## user_authorization_url = "http://oauth-sandbox.sevengoslings.net/authorize"
## acess_token_url =  "http://oauth-sandbox.sevengoslings.net/access_token"

## tho_legged =  "http://oauth-sandbox.sevengoslings.net/two_legged"
## three_legged = "http://oauth-sandbox.sevengoslings.net/three_legged"

## r5 = hurl.get("http://api.twitter.com/1/statuses/home_timeline.format",
##               debug=stdout_debug, allow_redirects=False,
##               auth=oauth)
## print(r5)
