#!/usr/bin/env python
# -*- coding:  utf-8 -*-

import human_curl as hurl

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


r1 = hurl.get("http://www.google.com",
              debug=stdout_debug, allow_redirects=True)

print(r1.cookiesjar)
r2 = hurl.get("http://h.wrttn.me/cookies/set/llllll/adkbhahjsbhjwbf",
              debug=stdout_debug, cookies=r1.cookiesjar)
assert r1.cookiesjar == r2.cookiesjar
print(r2.cookiesjar)
print(r2.content)
r3 = hurl.get("http://h.wrttn.me/cookies/set/222222/adkbhahjsbhjwbf",
              debug=stdout_debug, cookies=r1.cookiesjar)


print(r3.cookiesjar)
print(r3.content)

