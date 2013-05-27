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
from mod.common import TransWarpBase

VER = "\x05"


class TransWarpClient (TransWarpBase):

    def __init__ (self):
        TransWarpBase.__init__ (self)
        self.logger = Log ("client", config=config)
        self.engine.set_logger (self.logger)
        self.sock5_addr = config.SOCK5_ADDR
        self._sock5_users = config.SOCK5_USERS or {}
        ip = self.sock5_addr[0]
        arr = map (lambda x:chr(int(x)), ip.split ("."))
        self._sock5_server_id = struct.pack ("!4cH", arr[0], arr[1], arr[2], arr[3], self.sock5_addr[1])
        self.server_addr = config.SERVER_ADDR
        self.sock5_sock = None
        self.key = config.KEY


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


    def _send_sock5_unsupport (self, conn):
        self.logger.error ("peer %s not supported" % (str(conn.peer)))
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
                self.logger.info ("client %s: sent sock5 response" % (client.client_id))
                client.cli_state = proto.ClientState.CONNECTED
                self._check_client_state (client)
            else:
                self.logger.info ("client %s: sent sock5 err response and close" % (client.client_id))
                self.close_client (client)
            return
        self.engine.write_unblock (client.cli_conn, buf, __write_ok, self._on_err, cb_args=(client,))

    def _on_client_readable (self, cli_conn, client):
#        self.logger.debug ("client %s client readable" % (client.client_id))
        self.stream_to_fix (cli_conn, client.r_conn, client)


    def _on_remote_readable (self, r_conn, client):
#        self.logger.debug ("client %s remote readable" % (client.client_id))
        self.fix_to_stream (r_conn, client.cli_conn, client)


    def _on_server_connected (self, sock, client):
        self.logger.info ("client %s connected to server" % (client.client_id))
        r_conn = Connection (sock)
        _hash = proto.myhash (client.seed, self.key)
        auth_data = proto.AuthData (client.seed, _hash, self.key, client.r_host, client.r_port)
        buf = auth_data.serialize ()
        buf = proto.pack_head (len (buf)) + buf
        client.r_conn = r_conn

        def __on_remote_respond (r_conn, *args):
            resp = None
            try:
                buf = client.crypter_r.decrypt (r_conn.get_readbuf())
                resp = proto.ServerResponse.deserialize (buf)
                if resp.err_no:
                    self.logger.error ("client %s: %s %s" % (client.client_id, resp.err_no, resp.message))
                    self.close_client(client)
                else:
                    self.logger.info ("client %s server response" % (client.client_id))
                    client.r_state = proto.ClientState.CONNECTED 
                    self._check_client_state (client)
            except Exception, e:
                self.logger.exception ("client %s: server response error %s" % (client.client_id, str(e)))
                self.close_client(client)
                return

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
            self.logger.error ("zero len head")
            self.close_client(client)
            return
        def __write_ok (r_conn, *args):
            self.engine.read_unblock (r_conn, self.head_len, __on_read_head, self._on_err, cb_args=(client, ))
            return
        self.engine.write_unblock (r_conn, buf, __write_ok, self._on_err, cb_args=(client,))
        return self._send_sock5_reply (client, 0)


    def _connect_server (self, host, port, cli_conn):
        #self.logger.debug ("connecting server %s for %s:%s" % (self.server_addr, host, port))
        self.engine.remove_conn (cli_conn)
        seed = proto.random_string (16)
        client = proto.ClientData (host, port, cli_conn, seed, self.key)
        self.client_conn[client.client_id] = client
        def __on_connect_error (err, *args):
            self.logger.error ("client %s cannot connect to server, %s" % (client.client_id, str(err)))
            return self._send_sock5_reply (client, errno.EHOSTUNREACH)
        self.engine.connect_unblock (self.server_addr, self._on_server_connected, __on_connect_error, cb_args=(client, ))

    def _sock5_handshake (self, sock):
        print "handshake"
        conn = Connection (sock)
        def __on_ipv6_read (conn):
            print "ipv6"
            self._send_sock5_unsupport (conn)
            return
        def __on_domain_read (conn):
            print "domain"
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
            print "len", domain_len
            if domain_len > 0:
                return self.engine.read_unblock (conn, domain_len + 2, __on_domain_read)
            else:
                self.engine.close_conn (conn)
        def __on_ipv4_read (conn):
            print "ipv4"
            buf = conn.get_readbuf ()
            try:
                dst_addr = ".".join (map (lambda i: str(ord(i)), buf[0:4]))
                (dst_port,) = struct.unpack ("!H", buf[4:6])
                return self._connect_server (dst_addr, dst_port, conn) 
            except Exception, e:
                self.logger.exception (e)
                self.engine.close_conn (conn)
            return
        def __sock5_connect (conn, atyp):
            if atyp == 1: # IPV4
                return self.engine.read_unblock (conn, 6, __on_ipv4_read)
            elif atyp == 3: #DOMAIN 
                return self.engine.read_unblock (conn, 1, __on_domain_len)
            elif atyp == 4: # IPV6
                return self.engine.read_unblock (conn, 8, __on_ipv6_read)
            else:
                self.logger.exception ("unsupported sock5 atyp %d" % (atyp))
                self._send_sock5_unsupport (conn)
        def __on_socks_request (conn):
            buf = conn.get_readbuf ()
            ver, cmd, rsv, atyp = buf[0], ord(buf[1]), buf[2], ord(buf[3])
            if cmd == 1: # connect
                return __sock5_connect (conn, atyp)
            else:
                self.logger.exception ("unsupported sock5 cmd %d" % (cmd))
                self._send_sock5_unsupport (conn)
            return
        def __on_socks_no_auth (conn):
#            print "no auth"
            return self.engine.read_unblock (conn, 4, __on_socks_request)
        def __on_pw_read (conn, user):
            passwd = conn.get_readbuf ()
            _passwd = self._sock5_users.get (user)
            print "user auth", user, passwd
            if not self._sock5_users or passwd == _passwd:
                return self.engine.write_unblock (conn, "\x01" + "\x00", __on_socks_no_auth)
            else:
                return self.engine.write_unblock (conn, "\x01" + "\x01", self.engine.close_conn)
        def __on_user_read (conn):
            buf = conn.get_readbuf ()
            user = buf[0:-1]
            pw_len = ord(buf[-1])
            if pw_len == 0:
                return __on_pw_read (conn, user)
            elif pw_len > 255:
                return self.engine.close_conn (conn)
            return self.engine.read_unblock (conn, pw_len, __on_pw_read, cb_args=(user,))
        def __on_user_len (conn):
            buf = conn.get_readbuf ()
            ver, user_len = buf[0], ord(buf[1])
            if user_len > 255:
                return self.engine.close_conn (conn)
            return self.engine.read_unblock (conn, user_len + 1, __on_user_read)
        def __on_user_auth (conn):
            return self.engine.read_unblock (conn, 2, __on_user_len)
        def __on_select_methods (conn):
            buf = conn.get_readbuf ()
            if '\x00' in buf and not self._sock5_users:
                return self.engine.write_unblock (conn, VER + '\x00', __on_socks_no_auth)
            if '\x02' in buf:
                return self.engine.write_unblock (conn, VER + '\x02', __on_user_auth)
            return self._send_sock5_unsupport (conn)
        def __cb0 (conn):
            buf = conn.get_readbuf ()
            ver, nmethods = buf[0], ord(buf[1])
            if ver != VER:
                return self._send_sock5_unsupport (conn)
            return self.engine.read_unblock (conn, nmethods, __on_select_methods)
        self.engine.read_unblock (conn, 2, __cb0) # on error automatic close connection

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
