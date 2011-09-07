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


r1 = hurl.get("https://h.wrttn.me/basic-auth/username/password",
              debug=stdout_debug, allow_redirects=False,
              auth=("username", "password"))
print(r1)

r2 = hurl.get("https://h.wrttn.me/basic-auth/username/password",
              debug=stdout_debug, auth=("username", "password"))
print(r2)

r3 = hurl.get("https://h.wrttn.me/basic-auth/username/password",
              debug=stdout_debug, allow_redirects=False,
              auth=BasicAuth("username", "password"))

print(r3)



r4 = hurl.get("http://127.0.0.1:5000/digest-auth/auth/username/password",
             debug=stdout_debug, allow_redirects=False,
             auth=DigestAuth("username", "password"))
print(r4)


