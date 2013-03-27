#!/usr/bin/env python
# coding:utf-8

from lib.socket_engine import TCPSocketEngine, Connection
import lib.io_poll as io_poll
from lib.log import Log
import mod.proto as proto
import mod.crypter as crypter
import socket
import errno
import lib.daemon as daemon
import signal
import sys

import config_server as config

       

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

    def _new_client (self, sock):
        conn = Connection (sock)
        print "new"
        self.engine.read_unblock (conn, self.head_len, self._on_recv_head, None, cb_args=(self._auth, ))


    def _auth (self, cli_conn):
        print "auth"
        auth_data = None
        try:
            auth_data = proto.AuthData.deserialize (cli_conn.get_readbuf ())
        except Exception, e:
            self.logger.exception ("peer %s %s" % (cli_conn.peer, str(e)))
        key = proto.auth (auth_data.seed, auth_data._hash, self.auth_keys)
        if not key:
            self.logger.warn ("peer %s not authorized" % (cli_conn.peer))
            self.engine.close_conn (conn)
            return
        client = proto.ClientData (auth_data.r_host, auth_data.r_port, cli_conn, 
                auth_data.seed, auth_data._hash, name=key)
        self.engine.remove_conn (cli_conn)
        self.client_conn[client.client_id] = client
        self.logger.info ("client %s auth" % (client.client_id))
        client.state = proto.ClientState.CONNECTING
        self.engine.connect_unblock ((client.r_host, client.r_port), self._on_remote_conn, self._on_remote_conn_err, cb_args=(client, ))

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

    def _on_remote_readable (self, r_conn, client):
        buf = ""
        _buf = ""
        data = ""
        while True:
            print "remote read"
            try:
                _buf = r_conn.sock.recv (1024)
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
        print "client read"
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
            self.engine.write_unblock (client.r_conn, data, __write_ok, self._on_err, cb_args=(client, ))
            return
        self.engine.read_unblock (cli_conn, self.head_len, self._on_recv_head, __client_head_err, cb_args=(__on_client_read, __client_head_err))

    def _on_remote_conn (self, sock, client):
        client.state = proto.ClientState.CONNECTED
        self.logger.info ("client %s connected" % (client.client_id))
        client.r_conn = self.engine.put_sock (sock, readable_cb=self._on_remote_readable, readable_cb_args=(client,),
                idle_timeout_cb=self._on_idle)
        resp = proto.ServerResponse (0, "")
        buf = client.crypter_w.encrypt (resp.serialize ())
        def _write_ok (cli_conn, *args):
            self.engine.put_sock (cli_conn.sock, readable_cb=self._on_client_readable, readable_cb_args=(client,), 
                    idle_timeout_cb=self._on_idle)
            return
        self.engine.write_unblock (client.cli_conn, proto.pack_head (len (buf)) + buf, _write_ok, self._close_client)
        

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
        if self.passive_sock:
            self.engine.unlisten (self.passive_sock)
        self.is_running = False
        self.logger.info ("stopped")

    def loop (self):
        while self.is_running:
            self.engine.poll ()

stop_signal_flag = False
def main ():
    server = TransWarpServer ()
    def exit_sig_handler (sig_num, frm):
        global stop_signal_flag
        if stop_signal_flag:
            return
        stop_signal_flag = True
        server.stop ()
        return

    server.start ()
    signal.signal (signal.SIGTERM, exit_sig_handler)
    signal.signal (signal.SIGINT, exit_sig_handler)
    server.loop ()
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
        pid_file = "transwarp_srv.pid"
        mon_pid_file = "transwarp_srv_mon.pid"
        action = sys.argv[1]
        daemon.cmd_wrapper (action, main, usage, logger, config.log_dir, config.RUN_DIR, pid_file, mon_pid_file)


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 :
