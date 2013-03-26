#!/usr/bin/env python
# coding:utf-8

import hashlib
import struct
import pickle 
import string
import random

class PackError (Exception):
    pass

def myhash (s, key):
    _md5 = hashlib.md5 ()
    _md5.update (s + key)
    return _md5.hexdigest ()

def head_len ():
    return struct.calcsize ('!L')

def pack_head (length):
    return struct.pack ('!L', length)

def unpack_head (byte):
    (length, ) = struct.unpack("!L", byte)
    return length

def random_string (n):
    s = string.ascii_letters + string.digits
    result = ""
    for i in xrange (n):
        result += random.choice (s)
    return result
        
def gen_auth_data (key):
    seed = random_string (10)
    _hash = myhash (seed, key)
    return (seed, _hash)

def auth (seed, _hash, keys):
    """ find a matched key in our collection """
    for key in keys:
        if _hash == myhash (seed, key):
            return key
    return None


class AuthData (object):

    def __init__ (self, seed, _hash, r_host, r_port):
        self.seed = seed
        self._hash = _hash
        self.r_host = r_host
        self.r_port = r_port

    def serialize (self):
        return pickle.dumps ((self.seed, self._hash, self.r_host, self.r_port))

    @classmethod
    def deserialize (cls, buf):
        data = None
        try:
            data = pickle.loads (buf)
        except Exception, e:
            raise PackError ("%s unpickle error %s" % (cls.__name__, str(e)))
        if len (data) != 4:
            raise PackError ("%s format error" % (cls.__name__))
        return cls (data[0], data[1], data[2], data[3])



if __name__ == '__main__':
    assert unpack_head (pack_head (10)) == 10
    print "random", random_string (15)
    print "random", random_string (15)
    key = "sdfs98ulkdf"
    seed, _hash = gen_auth_data (key)
    print seed, _hash
    assert key == auth (seed, _hash, [key, "sssss"])

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
