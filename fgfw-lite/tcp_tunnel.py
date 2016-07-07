#!/usr/bin/env python
# coding:utf-8

import select
import socket
import errno
import logging
try:
    from socketserver import ThreadingTCPServer, StreamRequestHandler
except ImportError:
    from SocketServer import ThreadingTCPServer, StreamRequestHandler

from parent_proxy import ParentProxy
from connection import create_connection


logger = logging.getLogger('tcp_tunnel')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


class tcp_tunnel(ThreadingTCPServer):
    def __init__(self, proxy, target, server_address):
        self.proxy = ParentProxy('', proxy)
        self.target = target
        self.addr = server_address
        logger.info('starting tcp forward from %s(local) to %s(remote) via %s' % (server_address, target, self.proxy))
        ThreadingTCPServer.__init__(self, server_address, tcp_tunnel_handler)


class tcp_tunnel_handler(StreamRequestHandler):
    bufsize = 8196

    def handle(self):
        logger.info('tcp forward from %s(local) to %s(remote) via %s' % (self.server.addr, self.server.target, self.server.proxy))
        self.remotesoc = create_connection(self.server.target, ctimeout=5, parentproxy=self.server.proxy, tunnel=True)
        try:
            fd = [self.connection, self.remotesoc]
            while fd:
                ins, _, _ = select.select(fd, [], [], 60)
                if not ins:
                    break
                if self.connection in ins:
                    data = self.connection.recv(self.bufsize)
                    if data:
                        self.remotesoc.sendall(data)
                    else:
                        fd.remove(self.connection)
                        self.remotesoc.shutdown(socket.SHUT_WR)
                if self.remotesoc in ins:
                    data = self.remotesoc.recv(self.bufsize)
                    if data:
                        self.wfile.write(data)
                    else:
                        fd.remove(self.remotesoc)
                        self.connection.shutdown(socket.SHUT_WR)
        except socket.timeout:
            pass
        except (IOError, OSError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            for sock in [self.connection, self.remotesoc]:
                try:
                    sock.close()
                except (IOError, OSError):
                    pass
