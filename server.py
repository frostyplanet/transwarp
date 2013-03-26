#!/usr/bin/env python
# coding:utf-8

from lib.socket_engine import TCPSocketEngine, Connection
import lib.io_poll as io_poll
from lib.log import Log
import mod.proto as proto
import mod.crypter as crypter

import config_server as config

class ClientState ():
    NEW = "new"
    CONNECTING = "connecting"
    CONNECTED = "normal"


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
        

class TransWarpServer (object):

    def __init__ (self):
        self.engine = TCPSocketEngine (io_poll.get_poll(), is_blocking=False)
        self.logger = Log ("server", config=config)
        self.engine.set_logger (self.logger)
        self.engine.set_timeout (rw_timeout=60, idle_timeout=3600 * 12)
        self.is_running = False
        self.addr = config.SERVER_ADDR
        self.client_conn = dict ()
        self.head_len = proto.head_len ()
        self.auth_keys = config.ACCEPT_KEYS

    def _auth (self, conn):
        auth_data = None
        try:
            auth_data = proto.AuthData.deserialize (conn.get_readbuf ())
        except Exception, e:
            self.logger.exception ("peer %s %s" % (conn.peer, str(e)))
        key = proto.auth (auth_data.seed, auth_data._hash, self.auth_keys)
        if not key:
            self.logger.warn ("peer %s not authorized" % (conn.peer))
            self.engine.close_conn (conn)
            return
        client = ClientData (auth_data.r_host, auth_data.r_port, conn, 
                auth_data.seed, auth_data._hash, name=key)
        self.client_conn[client.client_id] = client
        self.logger.info ("client %s auth" % (client.client_id))
        client.state = ClientState.CONNECTING
        self.engine.connect_unblock ((r_host, r_port), self._on_remote_conn, self._on_remote_conn_err, cb_args=(client, ))

    def close_client (self, conn, client):
        if self.client_conn.has_key (client.client_id):
            del self.client_conn[client.client_id]
        if client.r_conn:
            self.engine.close_conn (client.r_conn)
        if client.cli_conn:
            self.engine.close_conn (client.cli_conn)
        client.state = ClientState.CLOSED
        self.logger.info ("client %s closed" % (client))

    def _close_client (self, conn, client):
        self.close_client (client)

    def _on_remote_readable (self, r_conn, client):
        buf = ""
        _buf = ""
        data = ""
        while True:
            try:
                _buf = r_conn.sock.read (1024)
                buf += _buf
            except (socket.error, e):
                if e.args[0] == errno.EAGAIN:
                    break
                elif e.args[0] == errno.EINTR:
                    continue
        if buf:
            data = client.crypter_w.encrypt (buf)
            data = proto.pack_head (len (data)) + data
        if not _buf:
            if buf:
                self.engine.close_conn (r_conn)
                client.r_conn = None
                return self.engine.write_unblock (client.cli_conn, data, self._close_client, self._on_err, cb_args=(client,))
            else:
                return self.close_client (client)
        else:
            self.engine.watch_conn (r_conn)
            def __write_ok (conn, *args):
                self.engine.watch_conn (client.cli_conn)
                return
            return self.engine.write_unblock (client.cli_conn, data, __write_ok, self._on_err, cb_args=(client, ))


    def _on_client_readable (self, cli_conn, client):
        def __client_head_err (cli_conn, *args):
            self.logger.debug ("client %s %s" % (client.client_id, cli_conn.error))
            self.close_client (client) 
            return
        def __write_ok (conn, *args):
            self.engine.watch_conn (client.r_conn)
            return
        def __on_client_read (cli_conn, *args):
            data = client.crypter_r.decrypt (cli_conn.get_readbuf ())
            self.engine.watch_conn (cli_conn)
            self.engine.write_unblock (client.r_conn, data, __write_ok, self.__on_err, cb_args=(client, ))
            return
        self.engine.read_unblock (conn, self.head_len, self._on_recv_head, __client_head_err, cb_args=(__on_client_read, __client_head_err))
        


    def _on_remote_conn (self, sock, client):
        client.state = ClientState.CONNECTED
        self.logger.info ("client %s connected" % (client.client_id))
        client.r_conn = self.engine.put_sock (sock, readable_cb=self._on_remote_readable, readable_cb_args=(client,), idle_timeout_cb=self._on_idle)
        

    def _on_remote_conn_err (self, r_conn, client):
        try:
            del self.client_conn[client.client_id]
        except:
            pass
        self.logger.warn ("client %s connection failed" % (client.client_id))
        #TODO notify client 

    def _on_idle (self, conn, client):
        #TODO
        pass

    def _on_err (self, conn, client):
        self.logger.error ("peer %s %s" % (conn.peer, conn.error))
        self.close_client (client)


    def _new_client (self, sock):
        conn = Connection (sock)
        self.engine.read_unblock (conn, self.head_len, self._on_recv_head, None, cb_args=(self._auth, )):

    def _on_recv_head (self, conn, msg_cb, head_err_cb=None):
        assert callable (msg_cb)
        try:
            data_len = proto.unpack_head (conn.get_readbuf ())
        except Exception, e:
            self.logger.exception (e)
            if callable (head_err_cb):
                head_err_cb (conn)
            return
        self.engine.read_unblock (conn, data_len, msg_cb, head_err_cb)

    def start (self): 
        if self.is_running:
            return
        self.passive_sock = self.engine.listen_addr (self.addr, readable_cb=None, new_conn_cb=self._new_client, backlog=50)
        self.is_running = True
        self.logger.info ("started")

    def stop (self):
        if not self.is_running:
            return
        self.engine.unlisten (self.passive_sock)
        self.is_running = False
        self.logger.info ("stopped")


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
