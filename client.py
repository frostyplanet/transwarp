#!/usr/bin/env python
# coding:utf-8

from lib.socket_engine import TCPSocketEngine, Connection
import lib.io_poll as io_poll
from lib.log import Log
import config_client as config
import mod.proto as proto
import socket
import lib.daemon as daemon
import errno
import struct
import os
import sys
import signal

VER = "\x05"
METHOD = "\x00"


class TransWarpClient (object):

    def __init__ (self):
        self.engine = TCPSocketEngine (io_poll.get_poll(), is_blocking=False)
        self.logger = Log ("client", config=config)
        self.engine.set_logger (self.logger)
        self.engine.set_timeout (rw_timeout=60, idle_timeout=3600)
        self.is_running = False
        self.sock5_addr = config.SOCK5_ADDR
        ip = self.sock5_addr[0]
        arr = map (lambda x:chr(int(x)), ip.split ("."))
        self._sock5_server_id = struct.pack ("!4cH", arr[0], arr[1], arr[2], arr[3], self.sock5_addr[1])
        self.server_addr = config.SERVER_ADDR
        self.sock5_sock = None
        self.client_conn = dict () # 
        self.key = config.KEY
        self.head_len = proto.head_len ()


    def start (self):
        if self.is_running:
            return
        self.sock5_sock = self.engine.listen_addr (self.sock5_addr, readable_cb=None, new_conn_cb=self._sock5_handshake, backlog=50)
        self.is_running = True

    def stop (self):
        if not self.is_running:
            return
        self.engine.unlisten (self.sock5_sock)
        self.is_running = False

    def loop (self):
        while self.is_running:
            self.engine.poll ()

    def _on_err (self, conn, client):
        self.logger.error ("peer %s %s" % (conn.peer, conn.error))
        self.close_client (client)

    def _on_idle (self, conn, client):
        self.logger.info ("client %s: closed due to idle" % (client.client_id))
        self.close_client(client)

    def _send_sock5_unsupport (self, conn):
        buf = "%s%s\x00\x01%s" % (VER, "\x07", self._sock5_server_id)
        def __write_ok (conn):
            self.engine.close_conn (conn)
            return
        self.engine.write_unblock (conn, buf, __write_ok)

    def _send_sock5_reply (self, client, err_no):
        if err_no == 0:
            status = "\x00"
        elif err_no == errno.ENETUNREACH:
            status = "\x03"
        elif err_no == errno.EHOSTUNREACH:
            status = "\x04"
        elif err_no == errno.ECONNREFUSED:
            status = "\x05"
        else:
            status = "\x01" # general error
        buf = "%s%s\x00\x01%s" % (VER, status, self._sock5_server_id)
        def __write_ok (cli_conn, *args):
            if err_no == 0:
                self.engine.put_sock (cli_conn.sock, readable_cb=self._on_client_readable, readable_cb_args=(client, ), idle_timeout_cb=self._on_idle)
                self.engine.put_sock (client.r_conn.sock, readable_cb=self._on_server_readable, readable_cb_args=(client, ), idle_timeout_cb=self._on_err)
            else:
                self.close_client (client)
            return
        self.engine.write_unblock (client.cli_conn, buf, __write_ok, self._on_err, cb_args=(client,))

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

    def _on_client_readable (self, cli_conn, client):
        buf = ""
        _buf = ""
        data = ""
        while True:
            try:
                _buf = cli_conn.sock.recv (1024)
                if not _buf:
                    break
                buf += _buf
            except socket.error, e:
                if e.args[0] == errno.EAGAIN:
                    break
                elif e.args[0] == errno.EINTR:
                    continue
                else:
                    self.logger.exception (e)
                    self.close_client(client)
                    return
        if buf:
            data = client.crypter_w.encrypt (buf)
            data = proto.pack_head (len (data)) + data
        if not _buf:
            if buf:
                self.engine.close_conn (cli_conn)
                client.cli_conn = None
                return self.engine.write_unblock (client.r_conn, data, self._close_client, self._on_err, cb_args=(client,))
            else:
                return self.close_client (client)
        else:
            self.engine.watch_conn (cli_conn)
            def __write_ok (conn, *args):
                self.engine.watch_conn (client.r_conn)
                return
            return self.engine.write_unblock (client.r_conn, data, __write_ok, self._on_err, cb_args=(client, ))



    def _on_server_readable (self, r_conn, client):
        def __server_head_err (r_conn, *args):
            self.logger.debug ("client %s %s" % (client.client_id, r_conn.error))
            self.close_client (client)
            return
        def __write_ok (conn, *args):
            self.engine.watch_conn (client.cli_conn)
            return
        def __on_server_read (r_conn, *args):
            data = client.crypter_r.decrypt (r_conn.get_readbuf ())
            self.engine.watch_conn (r_conn)
            self.engine.write_unblock (client.cli_conn, data, __write_ok, self._on_err, cb_args=(client, ))
            return
        self.engine.read_unblock (r_conn, self.head_len, self._on_recv_head, __server_head_err, 
                cb_args=(__on_server_read, __server_head_err))

    def _on_server_connected (self, sock, client):
        r_conn = Connection (sock)
        _hash = proto.myhash (client.seed, self.key)
        auth_data = proto.AuthData (client.seed, _hash, client.r_host, client.r_port)
        buf = auth_data.serialize ()
        buf = proto.pack_head (len (buf)) + buf
        client.r_conn = r_conn
        client.state = proto.ClientState.CONNECTED

        def __on_remote_respond (r_conn, *args):
            resp = None
            try:
                buf = client.crypter_r.decrypt (r_conn.get_readbuf())
                resp = proto.ServerResponse.deserialize (buf)
                self.logger.info ("client %s: %s %s" % (client.client_id, resp.err_no, resp.message))
            except Exception, e:
                self.logger.exception ("client %s: server response error %s" % (client.client_id, str(e)))
                return
            return self._send_sock5_reply (client, resp.err_no)

        def __on_read_head (r_conn, *args):
            data_len = 0
            try:
                data_len = proto.unpack_head (r_conn.get_readbuf ())
            except Exception, e:
                self.logger.error ("client %s remote head invalid" % (client.client_id))
                self.close_client (client)
                return
            if data_len > 0:
                self.engine.read_unblock (r_conn, data_len, __on_remote_respond, self._on_err, cb_args=(client, ))
                return
        def __write_ok (r_conn, *args):
            self.engine.read_unblock (r_conn, self.head_len, __on_read_head, self._on_err, cb_args=(client, ))
            return
        self.engine.write_unblock (r_conn, buf, __write_ok, self._on_err, cb_args=(client,))

    def close_client (self, client):
        if self.client_conn.has_key (client.client_id):
            del self.client_conn[client.client_id]
        if client.r_conn:
            self.engine.close_conn (client.r_conn)
        if client.cli_conn:
            self.engine.close_conn (client.cli_conn)
        client.state = proto.ClientState.CLOSED
        self.logger.info ("client %s closed" % (client))

    def _close_client (self, conn, client):
        self.close_client (client)



    def _connect_server (self, host, port, cli_conn):
        self.engine.remove_conn (cli_conn)
        seed = proto.random_string (16)
        client = proto.ClientData (host, port, cli_conn, seed, self.key)
        self.client_conn[client.client_id] = client
        def __on_connect_error (err, *args):
            self.logger.error ("client %s cannot connect to server, %s" % (client.client_id, str(err)))
            self.close_client (client)
            return
        self.engine.connect_unblock (self.server_addr, self._on_server_connected, __on_connect_error, cb_args=(client, ))

    def _sock5_handshake (self, sock):
        print "handshake"
        conn = Connection (sock)
        def __on_ipv6_read (conn):
            self._send_sock5_unsupport (conn)
            return
        def __on_domain_read (conn):
            buf = conn.get_readbuf ()
            domain_len = len(buf) - 2
            try:
                (domain, dst_port) = struct.unpack ("!%dsH"% (domain_len), buf)
                return self._connect_server (domain, dst_port, conn)
            except Exception, e:
                self.logger.exception (e)
                self.engine.close_conn (conn)
            return
        def __on_domain_len (conn):
            domain_len = ord (conn.get_readbuf ())
            if domain_len > 0:
                return self.engine.read_unblock (conn, domain_len + 2, __on_domain_read)
            else:
                self.engine.close_conn (conn)
        def __on_ipv4_read (conn):
            buf = conn.get_readbuf ()
            try:
                dst_addr = ".".join (map (lambda i: str(ord(i)), buf[0:4]))
                (dst_port,) = struct.unpack ("!H", buf[4:6])
                return self._connect_server (dst_addr, dst_port, conn) 
            except Exception, e:
                self.logger.exception (e)
                self.engine.close_conn (conn)
        def __on_auth_type_read (conn):
            buf = conn.get_readbuf ()
            ver, cmd, rsv, atyp = buf[0], buf[1], buf[2], buf[3]
            if atyp == "\x01": # IPV4
                return self.engine.read_unblock (conn, 6, __on_ipv4_read)
            elif atyp == "\x03": #DOMAIN 
                return self.engine.read_unblock (conn, 1, __on_domain_len)
            elif atyp == "\x04": # IPV6
                return self.engine.read_unblock (conn, 8, __on_ipv6_read)
            else:
                self._send_sock5_unsupport (conn)
        def __cb2 (conn):
            print "cb2"
            return self.engine.read_unblock (conn, 4, __on_auth_type_read)
        def __cb1 (conn):
            return self.engine.write_unblock (conn, VER + METHOD, __cb2)
        self.engine.read_unblock (conn, 3, __cb1) # on error automatic close connection

stop_signal_flag = False

def main ():
    twclient = TransWarpClient ()

    def exit_sig_handler (sig_num, frm):
        global stop_signal_flag
        if stop_signal_flag:
            return
        stop_signal_flag = True
        twclient.stop ()
        return
    twclient.start ()
    signal.signal (signal.SIGTERM, exit_sig_handler)
    signal.signal (signal.SIGINT, exit_sig_handler)
    twclient.loop ()
    return
        
def usage ():
    print "usage:\t%s star/stop/restart\t#manage forked daemon" % (sys.argv[0])
    print "\t%s run\t\t# run without daemon, for test purpose" % (sys.argv[0])
    os._exit (1)

if __name__ == '__main__':
    if len (sys.argv) <= 1:
        usage ()
    else:
        logger = Log ("daemon", config=config) # to ensure log is permitted to write
        pid_file = "transwarp_agent.pid"
        mon_pid_file = "transwarp_agent_mon.pid"
        action = sys.argv[1]
        daemon.cmd_wrapper (action, main, usage, logger, config.log_dir, config.RUN_DIR, pid_file, mon_pid_file)


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
