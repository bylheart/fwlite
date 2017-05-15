#!/usr/bin/env python
# coding:utf-8

from builtins import chr

import struct
import encrypt
import hashlib
import hmac
import io
import socket
import select
import errno
import backports.socketpair
from threading import Thread
import traceback
import logging

logger = logging.getLogger('sssocket')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

from parent_proxy import ParentProxy


class sssocket(object):
    bufsize = 65519

    def __init__(self, ssServer, ctimeout=5, parentproxy=None):
        if ssServer and not isinstance(ssServer, ParentProxy):
            ssServer = ParentProxy(ssServer, ssServer)
        self.ssServer = ssServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.crypto = None
        self._socketpair_a, self._socketpair_b = socket.socketpair()
        self.__ota = False
        self._ota_chunk_idx = 0
        self._thread = None

    def connect(self, address):
        self.__address = address
        sshost, ssport, ssmethod, sspassword = (self.ssServer.hostname, self.ssServer.port, self.ssServer.username.lower(), self.ssServer.password)
        from connection import create_connection
        if ssmethod.endswith('-auth'):
            self.__ota = True
            ssmethod = ssmethod[:-5]
        self._sock = create_connection((sshost, ssport), self.timeout, parentproxy=self.parentproxy, tunnel=True)
        self._rfile = self._sock.makefile('rb')
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        host, port = self.__address

        addrtype = 19 if self.__ota else 3
        header = b''.join([chr(addrtype).encode(),
                           chr(len(host)).encode('latin1'),
                           host.encode(),
                           struct.pack(b">H", port)])
        if self.__ota:
            key = self.crypto.cipher_iv + self.crypto.key
            header += hmac.new(key, header, hashlib.sha1).digest()[:10]
        self._sock.sendall(self.crypto.encrypt(header))
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
                    data = remote.recv(self.bufsize)
                    if not data:
                        break
                    local.sendall(cipher.decrypt(data))
                if local in ins:
                    data = local.recv(self.bufsize)
                    if not data:
                        break
                    if self.__ota:
                        # modified from https://github.com/shadowsocks/shadowsocks/blob/master/shadowsocks/tcprelay.py
                        data_len = struct.pack(">H", len(data))
                        index = struct.pack('>I', self._ota_chunk_idx)
                        key = self.crypto.cipher_iv + index
                        sha110 = hmac.new(key, data, hashlib.sha1).digest()[:10]
                        self._ota_chunk_idx += 1
                        data = data_len + sha110 + data
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
