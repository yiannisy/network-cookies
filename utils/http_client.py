#!/usr/bin/env python
import cookies, requests
import sys

# Static Cookie Descriptor
CHIP = 0x1
seed = "malakas"
cookie_descriptor = cookies.CookieDescriptor(CHIP, seed)

cookie = cookie_descriptor.generateTextCookie()
print "Network Cookie: %s" % cookie.toBase64()
headers = {'network-cookie':cookie.toBase64()}
r = requests.get(sys.argv[1], headers=headers)
print "Response : %s" % r
