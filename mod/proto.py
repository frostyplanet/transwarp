#!/usr/bin/env python
# coding:utf-8

import hashlib
import struct
import pickle 
import string
import random

class PackError (Exception):
    pass

MAGIC = 0xdf358
FORMAT = "!IL"

def myhash (s, key):
    _md5 = hashlib.md5 ()
    _md5.update (s + key)
    return _md5.hexdigest ()

def head_len ():
    return struct.calcsize (FORMAT)

def pack_head (length):
    return struct.pack (FORMAT, MAGIC, length)

def unpack_head (byte):
    (magic, length, ) = struct.unpack(FORMAT, byte)
    if magic != MAGIC:
        raise Exception ("head invalid")
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

    def __init__ (self, seed, _hash, key, r_host, r_port):
        self.seed = seed
        self._hash = _hash
        self.key = key
        self.r_host = r_host
        self.r_port = r_port

    def serialize (self):
        c = crypter.MyCryptor(self.key, self.seed, 128)
        dest = c.encrypt (pickle.dumps ((self.r_host, self.r_port)))
        return pickle.dumps ((self.seed, self._hash, dest))

    @classmethod
    def deserialize (cls, buf, keys):
        data = None
        try:
            data = pickle.loads (buf)
        except Exception, e:
            raise PackError ("%s unpickle error %s" % (cls.__name__, str(e)))
        if len (data) != 3:
            raise PackError ("%s format error" % (cls.__name__))
        seed = data[0]
        _hash = data[1]
        key = auth (seed, _hash, keys)
        if not key:
            return None
        dest = None
        try:
            c = crypter.MyCryptor(key, seed, 128)
            dest = pickle.loads (c.decrypt (data[2]))
        except Exception, e: 
            raise PackError ("%s dest format error %s" % (cls.__name__, str(e)))
        if len (dest) != 2:
            raise PackError ("%s format error" % (cls.__name__))
        return cls (seed, _hash, key, dest[0], dest[1])

class ServerResponse (object):

    def __init__ (self, err_no, message):
        """ when err_no == 0 means no error """
        self.err_no = err_no
        self.message = message

    def serialize (self):
        return pickle.dumps((self.err_no, self.message))

    @classmethod
    def deserialize (cls, buf):
        data = None
        try:
            data = pickle.loads (buf)
        except Exception, e:
            raise PackError ("%s unpickle error %s" % (cls.__name__, str(e)))
        if len (data) != 2:
            raise PackError ("%s format error" % (cls.__name__))
        return cls (data[0], data[1])


class ClientState:
    NEW = "new"
    CONNECTING = "connecting"
    CONNECTED = "normal"
    CLOSED = "closed"


class ClientData (object):

    def __init__ (self, r_host, r_port, cli_conn, seed, key, name=None):
        self.state = ClientState.NEW
        self.cli_conn = cli_conn
        self.r_conn = None
        self.r_host = r_host
        self.r_port = r_port
        self.client_id = "%s:%s-%s:%s" % (cli_conn.peer[0], cli_conn.peer[1], r_host, r_port)
        self.seed = seed
        self.key = key
        self.name = name
        self.crypter_r = crypter.MyCryptor(key, seed, 128)
        self.crypter_w = crypter.MyCryptor(key, seed, 128)
        self.passive_sock = None
 
import crypter # avoid cycle import

if __name__ == '__main__':
    assert unpack_head (pack_head (10)) == 10
    print "random", random_string (15)
    print "random", random_string (15)
    key = "sdfs98ulkdf"
    seed, _hash = gen_auth_data (key)
    print seed, _hash
    assert key == auth (seed, _hash, [key, "sssss"])
    a = AuthData (seed, _hash, key, "g.cn", 88)
    d = AuthData.deserialize (a.serialize (), [key, "hahahaha"])
    assert d

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
