#!/usr/bin/env python
import cookies, requests
import sys
import subprocess, shlex

# Static Cookie Descriptor
id = int(sys.argv[2])
key = "test"
cookie_descriptor = cookies.CookieDescriptor(id, key)

cookie = cookie_descriptor.generateTextCookie()

cmd = 'wget --header=network-cookie:%s %s' % (cookie.toBase64(), sys.argv[1])
subprocess.call(shlex.split(cmd))

