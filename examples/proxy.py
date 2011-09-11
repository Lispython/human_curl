#!/usr/bin/env python
# -*- coding:  utf-8 -*-

import human_curl as hurl

r = hurl.get("http://nntime.com/proxy-country/China-63.htm", debug=hurl.utils.stdout_debug,
             proxy = ('socks4', ("69.59.140.30", 1080 )))


print(r)
print(r.headers)
