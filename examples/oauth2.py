#!/usr/bin/env python
# -*- coding:  utf-8 -*-

import human_curl as hurl
from human_curl.auth import *

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


request_token_url = "http://oauth-sandbox.sevengoslings.net/request_token"
authorize_url = "http://oauth-sandbox.sevengoslings.net/authorize"
access_token_url = "http://oauth-sandbox.sevengoslings.net/access_token"
protected_resource = "http://oauth-sandbox.sevengoslings.net/two_legged"


consumer_key = "be4b2eab12130803"
consumer_secret = "a2e0e39b27d08ee2f50c4d3ec06f"


r = hurl.Request("GET", protected_resource,
            debug=stdout_debug
            )

consumer = OAuthConsumer(consumer_key, consumer_secret)

oauth_manager = OAuthManager(consumer, request_token_url=request_token_url,
                             authorize_url=authorize_url,
                             access_token_url=access_token_url,
                             signature_method=SignatureMethod_PLAINTEXT)

oauth_manager.setup_request(r)
oauth_manager.request_token()

print(oauth_manager._tmp_token_key, oauth_manager._tmp_token_secret)
print(oauth_manager.confirm_url)

# oauth_manager.verify(pin)

#oauth_manager.access_request()
