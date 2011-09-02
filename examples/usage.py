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


print("Test simple request")
r1 = hurl.get("http://google.com")
print(r1)
print(r1.headers)

print("Test redirects")
r2 = hurl.get("http://google.com", allow_redirects=True)
print(r2)
print(r2.history)
print(r2.headers)
print(r2._headers_history)
print(r2.cookies)
print(r2.cookiesjar)

print("Test debug_output")
r3 = hurl.post("http://www.google.com", debug=stdout_debug,
               data={"hello_key": "hello_value"}, params={"yandex": "googling"})

print(r3.status_code)


