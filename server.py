#!/usr/bin/env python
# coding:utf-8

from lib.socket_engine import TCPSocketEngine, Connection
import lib.io_poll as io_poll
from lib.log import Log
import mod.proto as proto
import mod.crypter as crypter
import socket
import lib.daemon as daemon
import signal
import sys
import os

import config_server as config
from mod.common import TransWarpBase
       

class TransWarpServer (TransWarpBase):

    def __init__ (self):
        TransWarpBase.__init__ (self)
        self.logger = Log ("server", config=config)
        self.engine.set_logger (self.logger)
        self.addr = config.SERVER_ADDR
        self.auth_keys = config.ACCEPT_KEYS
        self.passive_sock = None

    def _new_client (self, sock):
        conn = Connection (sock)
        print "new %s" % (str(conn.peer))
        self.engine.read_unblock (conn, self.head_len, self._on_recv_head, None, cb_args=(self._auth, ))


    def _auth (self, cli_conn):
        auth_data = None
        try:
            auth_data = proto.AuthData.deserialize (cli_conn.get_readbuf (), self.auth_keys)
        except Exception, e:
            self.logger.exception ("peer %s %s" % (cli_conn.peer, str(e)))
        if not auth_data:
            self.logger.warn ("peer %s not authorized" % (str(cli_conn.peer)))
            self.engine.close_conn (cli_conn)
            return
        client = proto.ClientData (auth_data.r_host, auth_data.r_port, cli_conn, 
                auth_data.seed, auth_data.key)
        self.engine.remove_conn (cli_conn)
        self.client_conn[client.client_id] = client
        self.logger.info ("client %s auth" % (client.client_id))
        client.state = proto.ClientState.CONNECTING
        self.engine.connect_unblock ((client.r_host, client.r_port), self._on_remote_conn, self._on_remote_conn_err, cb_args=(client, ))

    def _on_remote_readable (self, r_conn, client):
        print "remote %s readable" % (client.client_id)
        self.stream_to_fix (r_conn, client.cli_conn, client)


    def _on_client_readable (self, cli_conn, client):
        print "client %s readable" % (client.client_id)
        self.fix_to_stream (cli_conn, client.r_conn, client)

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
        self.engine.write_unblock (client.cli_conn, proto.pack_head (len (buf)) + buf, _write_ok, self._on_err)
        

    def _on_remote_conn_err (self, error, client):
        self.logger.warn ("client %s: connection failed, %s" % (client.client_id, str(error)))
        resp = proto.ServerResponse (error.args[0], error.args[1])
        buf = client.crypter_w.encrypt (resp.serialize ())
        def _write_ok (cli_conn, *args):
            self.close_client (client)
            return
        self.engine.write_unblock (client.cli_conn, proto.pack_head (len (buf)) + buf, _write_ok, self._on_err)

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
