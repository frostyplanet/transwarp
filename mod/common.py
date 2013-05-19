#!/usr/bin/env python
# coding:utf-8

from lib.socket_engine import TCPSocketEngine, Connection
import lib.io_poll as io_poll
from lib.log import Log
import mod.proto as proto
import errno
import socket


class TransWarpBase (object):

    logger = None

    def __init__ (self):
        self.engine = TCPSocketEngine (io_poll.get_poll(), is_blocking=False, debug=True)
        self.client_conn = dict () # 
        self.head_len = proto.head_len ()
        self.is_running = False
        self.engine.set_timeout (rw_timeout=120, idle_timeout=600)

    def _on_recv_head (self, conn, msg_cb, head_err_cb=None):
        assert callable (msg_cb)
        try:
            data_len = proto.unpack_head (conn.get_readbuf ())
        except Exception, e:
            conn.error = e
            if callable (head_err_cb):
                head_err_cb (conn)
            return
        self.engine.read_unblock (conn, data_len, msg_cb, head_err_cb)

    def _check_client_state (self, client):
        if client.cli_state == proto.ClientState.CONNECTED and client.r_state == proto.ClientState.CONNECTED:
            self.engine.put_sock (client.cli_conn.sock, readable_cb=self._on_client_readable, readable_cb_args=(client,), 
                    idle_timeout_cb=self._on_idle)
            self.engine.put_sock (client.r_conn.sock, readable_cb=self._on_remote_readable, readable_cb_args=(client,),
                    idle_timeout_cb=self._on_idle)
            self.logger.info ("client %s establish both connection" % (client.client_id))
        elif client.cli_state == proto.ClientState.CONNECTED:
            self.engine.remove_conn (client.cli_conn)
        elif client.r_state == proto.ClientState.CONNECTED:
            self.engine.remove_conn (client.r_conn)


    def loop (self):
        while self.is_running:
            self.engine.poll (timeout=10)

    def _on_err (self, conn, client):
        self.logger.error ("client %s: peer %s %s" % (client.client_id, conn.peer, conn.error))
        self.close_client (client)

    def _on_idle (self, conn, client):
        self.logger.info ("client %s: closed due to idle" % (client.client_id))
        self.close_client(client)

    def close_client (self, client):
        if self.client_conn.has_key (client.client_id):
            del self.client_conn[client.client_id]
        if client.r_conn and client.r_conn.is_open:
            self.engine.close_conn (client.r_conn)
        if client.cli_conn and client.cli_conn.is_open:
            self.engine.close_conn (client.cli_conn)
        client.state = proto.ClientState.CLOSED

    def _close_client (self, conn, client):
        self.close_client (client)


    def stream_to_fix (self, stream_conn, fix_conn, client):

        def __send_and_close (client, data):
            self.logger.error ("client %s: peer close" % (client.client_id))
            if not data:
                return self.close_client (client)
            self.engine.close_conn (stream_conn)
            data = client.crypter_w.encrypt (data)
            data = proto.pack_head (len (data)) + data
            def __write_ok (conn, *args):
                self.engine.close_conn (fix_conn)
                return
            return self.engine.write_unblock (fix_conn, data, __write_ok, self._on_err, cb_args=(client, ))

        def __send_and_watch (client, data):
            def __write_ok (conn, *args):
                self.engine.watch_conn (stream_conn)
                return
            data = client.crypter_w.encrypt (data)
            data = proto.pack_head (len (data)) + data
#            self.engine.remove_conn (stream_conn)
            return self.engine.write_unblock (fix_conn, data, __write_ok, self._on_err, cb_args=(client, ))
            
        buf = ""
        _buf = ""
        try:
            while True:
                try:
                    _buf = stream_conn.sock.recv (16 * 1024)
                    if len(_buf) == 0:
                        return __send_and_close (client, buf)
                    buf += _buf
                except socket.error, e:
                    if e.args[0] == errno.EAGAIN:
                        break
                    elif e.args[0] == errno.EINTR:
                        continue
                    else:
                        self.logger.error ("client %s: %s" % (client.client_id, e))
                        self.close_client(client)
                        return
            __send_and_watch (client, buf)
        except Exception, e:
            self.logger.exception (e)
            self.close_client (client)


    def fix_to_stream (self, fix_conn, stream_conn, client):
        try:
            def __head_err (fix_conn, *args):
                self.logger.error ("client %s %s" % (client.client_id, fix_conn.error))
                self.close_client (client)
                return
            def __write_ok (conn, *args):
                self.engine.watch_conn (fix_conn)
                return
            def __on_fix_read (fix_conn, *args):
                try:
#                    self.engine.remove_conn (fix_conn)
                    data = client.crypter_r.decrypt (fix_conn.get_readbuf ())
                    self.engine.write_unblock (stream_conn, data, __write_ok, self._on_err, cb_args=(client, ))
                except Exception, e:
                    self.logger.exception ("client %s: response error %s" % (client.client_id, str(e)))
                    self.close_client(client)
                return
            self.engine.read_unblock (fix_conn, self.head_len, self._on_recv_head, __head_err, 
                    cb_args=(__on_fix_read, __head_err))
        except Exception, e:
            self.logger.exception (e)
            self.close_client (client)


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
