#!/usr/bin/env python
# coding:utf-8

from builtins import chr

import struct
import socket
import select
import errno
from threading import Thread
import traceback
import logging

import encrypt

import backports.socketpair
from parent_proxy import ParentProxy

logger = logging.getLogger('sssocket')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

CTX = b"ss-subkey"


class sssocket(object):
    bufsize = 8192

    def __init__(self, ssServer, ctimeout=5, parentproxy=None):
        if ssServer and not isinstance(ssServer, ParentProxy):
            ssServer = ParentProxy(ssServer, ssServer)
        self.ssServer = ssServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.crypto = None
        self.aead = False
        self._socketpair_a, self._socketpair_b = socket.socketpair()
        self._ota_chunk_idx = 0
        self._thread = None

    def connect(self, address):
        self.__address = address
        sshost, ssport, ssmethod, sspassword = (self.ssServer.hostname, self.ssServer.port, self.ssServer.username.lower(), self.ssServer.password)
        from connection import create_connection

        self._sock = create_connection((sshost, ssport), self.timeout, parentproxy=self.parentproxy, tunnel=True)
        self._rfile = self._sock.makefile('rb')
        try:
            self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        except ValueError:
            self.crypto = encrypt.AEncryptor_AEAD(sspassword, ssmethod, CTX)
            self.aead = True

        self._connected = False

        # start forward thread here
        self._thread = Thread(target=self.forward_tcp, args=(self._socketpair_b, self._sock, self.crypto, 60))
        self._thread.start()

    def forward_tcp(self, local, remote, cipher, timeout=60):
        # remote: self._sock, connected to server
        # local: self._socketpair_b, connected to client
        try:
            while 1:
                ins, _, _ = select.select([local, remote], [], [], timeout)
                if not ins:
                    break
                if remote in ins:
                    if self.aead:
                        if not cipher._decryptor:
                            data = self._rfile.read(cipher._iv_len)
                            cipher.decrypt(data)
                        _len = self._rfile.read(18)
                        if not _len:
                            break
                        _len, = struct.unpack("!H", cipher.decrypt(_len))
                        ct = self._rfile.read(_len+16)
                        local.sendall(cipher.decrypt(ct))
                    else:
                        data = remote.recv(self.bufsize)
                        if not data:
                            break
                        local.sendall(cipher.decrypt(data))
                if local in ins:
                    data = local.recv(self.bufsize)
                    if not data:
                        break
                    if not self._connected:
                        host, port = self.__address

                        header = b''.join([chr(3).encode(),
                                           chr(len(host)).encode('latin1'),
                                           host.encode(),
                                           struct.pack(b">H", port)])
                        data = header + data
                        self._connected = True

                    remote.sendall(cipher.encrypt(data))
        except socket.timeout:
            logger.info('socket.timeout')
        except (OSError, IOError) as e:
            if e.args[0] in (errno.EBADF,):
                return
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        except Exception as e:
            logger.error(repr(e))
            logger.error(traceback.format_exc())
        finally:
            for sock in (remote, local):
                try:
                    sock.close()
                except (OSError, IOError):
                    pass

    def recv(self, size):
        return self._socketpair_a.recv(size)

    def sendall(self, data):
        return self._socketpair_a.sendall(data)

    def makefile(self, mode='rb', bufsize=0):
        return self._socketpair_a.makefile(mode, bufsize)

    def settimeout(self, value):
        return self._socketpair_a.settimeout(value)

    def setsockopt(self, level, optname, value):
        return self._socketpair_a.setsockopt(level, optname, value)

    def fileno(self):
        return self._socketpair_a.fileno()

    def shutdown(self, how):
        return self._socketpair_a.shutdown(how)

    def close(self):
        return self._socketpair_a.close()


if __name__ == '__main__':
    s = sssocket('ss://aes-128-cfb:password@127.0.0.1:8138', 5)
    s.connect(('www.baidu.com', 80))
    s.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = s.recv(1024)
    while data:
        print(repr(data))
        data = s.recv(1024)
