import hmac,uuid
import time, struct, string
from base64 import b64encode, b64decode
from hashlib import sha1

NCT = 25 # Network Coherency Time in seconds

class CookieException(Exception):
    pass

class CookieDescriptor(object):
    def __init__(self, id=None, key=None):
        self.id = id
        self.key = key
        self.used = {}

    def toString(self):
        str_ = "%s,%s" % (self.id, self.key)
        return str_

    def generateCookie(self):
        cookie = Cookie(self.id, self.key)
        return cookie

    def generateTextCookie(self):
        cookie = TextCookie(self.id, self.key)
        return cookie

    def verifyCookie(self, cookie):
        if (cookie.id != self.id):
            raise CookieException("Invalid cookie id (self:%d, given:%d)" % (self.id, cookie.id))

        if (abs(cookie.timestamp - time.time()) > NCT):
            raise CookieException("Cookie timestamp expired (now:%d, timestamp:%d, NCT :%d)" % 
                                  (time.time(), cookie.timestamp, NCT))

        if (cookie.uuid in self.used):
            raise CookieException("Cookie already used (id:%d, UUID :%s)" % (cookie.id, cookie.uuid))

        digest = hmac.new(self.key, struct.pack('QQ16s', cookie.id, cookie.timestamp, cookie.uuid)).digest()
        if (cookie.sig != digest):
            raise CookieException("Invalid cookie signature (calculated:%s, given:%s)" % (digest, cookie.sig))

        # If we made it all the way here we are good to go...
        self.used[cookie.uuid] = True
        return True
        
    def verifyTextCookie(self, cookie):
        if (cookie.id != self.id):
            raise CookieException("Invalid cookie id (self:%d, given:%d)" % (self.id, cookie.id))

        if (abs(cookie.timestamp - time.time()) > NCT):
            raise CookieException("Cookie timestamp expired (now:%d, timestamp:%d, NCT :%d)" % 
                                  (time.time(), cookie.timestamp, NCT))

        if (cookie.uuid in self.used):
            raise CookieException("Cookie already used (id:%d, UUID :%s)" % (cookie.id, cookie.uuid))

        digest = hmac.new(self.key, '%d\r\n%d\r\n%s' % (cookie.id,cookie.timestamp, cookie.uuid), sha1).hexdigest()
        if (cookie.sig != digest):
            raise CookieException("Invalid cookie signature (id:%d, timestamp:%d, uuid:%s, calculated:%s, given:%s)" % (cookie.id, cookie.timestamp, cookie.uuid, digest, cookie.sig))

        # If we made it all the way here we are good to go...
        self.used[cookie.uuid] = True
        return True

    def __str__(self):
        return self.toString()

class Cookie(object):
    def __init__(self, id, key=None, timestamp=None, r_uuid=None, sig=None):
        self.id = id
        self.key = key
        if timestamp == None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        if r_uuid == None:
            self.uuid = uuid.uuid4().bytes
        else:
            self.uuid = r_uuid
        value = struct.pack('QQ16s', self.id, self.timestamp, self.uuid)
        if sig == None:
            self.sig = hmac.new(self.key, value).digest()
        else:
            self.sig = sig

    def toBytes(self):
        buf = struct.pack('QQ16s16s', self.id, self.timestamp, self.uuid, self.sig)
        return buf
    
    def toBase64(self):
        return b64encode(self.toBytes())

    @classmethod
    def fromBytes(cls, buf):
        id, timestamp, r_uuid, sig = struct.unpack('QQ16s16s', buf) 
        return cls(id=id, timestamp = timestamp, r_uuid = r_uuid, sig=sig)

    @classmethod
    def fromBase64(cls, str_):
        s = b64decode(str_)
        return cls.fromBytes(s)

    def __str__(self):
        return "%x, %x, %s, %s" % (self.id, self.timestamp, b64encode(self.uuid), b64encode(self.sig))

class TextCookie(object):
    def __init__(self, id, key=None, timestamp=None, r_uuid=None, sig=None):
        self.id = id
        self.key = key
        if timestamp == None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        # make sure that our cookie doesn't contain the special delimiter character \r\n 
        while True:
            if r_uuid == None:
                self.uuid = str(uuid.uuid4())
            else:
                self.uuid = r_uuid
            value = '%d\r\n%d\r\n%s' % (self.id, self.timestamp, self.uuid)
            if sig == None:
                self.sig = hmac.new(self.key, value, sha1).hexdigest()
            else:
                self.sig = sig
            val = '%d\r\n%d\r\n%s\r\n%s' % (self.id, self.timestamp, self.uuid, self.sig)
            if string.count(val,"\r\n") != 3:
                continue
            break

    def toBase64(self):
        val = '%d\r\n%d\r\n%s\r\n%s' % (self.id, self.timestamp, self.uuid, self.sig)
        return b64encode(val)

    @classmethod
    def fromBase64(cls, str_):
        try:
            s = b64decode(str_)
            id, timestamp, r_uuid, sig = string.split(s, '\r\n')
            id = int(id)
            timestamp = int(timestamp)
        except Exception as e:
            raise CookieException("Cannot extract cookie fields from raw value (%s, %s, %s)" % (str_, s, e))
        try:
            return cls(id=id, timestamp=timestamp, r_uuid=r_uuid, sig=sig)
        except Exception as e:
            raise CookieException("Cannot generate cookie (%s)" % e)

    def __str__(self):
        return "%x, %x, %s, %s" % (self.id, self.timestamp, b64encode(self.uuid), b64encode(self.sig))



def load_standard_descriptors(fname='cookie_descriptors.txt', asDict=False):
    if asDict == False:
        descriptors = []
    else:
        descriptors = {}
    f = open(fname,'r')
    for l in f.readlines()[1:]:
        vals = string.split(l.rstrip(),',')
        id = int(vals[0], 16)
        key = vals[1]
        if asDict == False:
            descriptors.append(CookieDescriptor(id, key))
        else:
            descriptors[id] = CookieDescriptor(id, key)
    f.close()
    return descriptors

