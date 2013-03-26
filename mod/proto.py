#!/usr/bin/env python
# coding:utf-8

import hashlib
import struct
import pickle 
import string
import random
from Crypto.Cipher import AES

def myhash (s, key):
    _md5 = hashlib.md5 ()
    _md5.update (s + key)
    return _md5.hexdigest ()


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


def fix_len (s, byte_len):
    l = len (s)
    if l < byte_len:
        return  s + (byte_len - l) * 'x'
    elif l > byte_len:
        return key[0 : byte_len]

class MyCryptor (object):

    def __init__ (self, key, iv, block_size):
        self.byte_len = block_size / 8
        self.key = fix_len (key, self.byte_len)
        self.iv = fix_len (iv, self.byte_len)
        self.cy_obj = AES.new (self.key, AES.MODE_CFB, self.iv)

    def encrpy (self, data):
        return self.cy_obj.encrypt (data)

    def decrypt (self, buf):
        return self.cy_obj.decrypt (buf)



if __name__ == '__main__':
    assert unpack_head (pack_head (10)) == 10
    print "random", random_string (15)
    print "random", random_string (15)
    key = "sdfs98ulkdf"
    seed, _hash = gen_auth_data (key)
    print seed, _hash
    assert auth (seed, _hash, [key, "sssss"])
    arr = [random_string (8), random_string (35), random_string (133)]
    aes_key = "dsf343242"
    c1 = MyCryptor (aes_key, "aaa", 128)
    c2 = MyCryptor (aes_key, "aaa", 128)
    for i in arr:
        b1 = c1.encrpy (i)
        b2 = c2.decrypt (b1)
        assert i == b2


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
