#!/usr/bin/env python
# coding:utf-8
import struct
import encrypt
import io
from parent_proxy import ParentProxy
from basesocket import basesocket


class sssocket(basesocket):
    bufsize = 8192

    def __init__(self, ssServer=None, ctimeout=1, parentproxy=None, iplist=None):
        basesocket.__init__(self)
        if ssServer and not isinstance(ssServer, ParentProxy):
            ssServer = ParentProxy(ssServer, ssServer)
        self.ssServer = ssServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.crypto = None
        self.connected = False

    def connect(self, address):
        self.__address = address
        sshost, ssport, ssmethod, sspassword = (self.ssServer.hostname, self.ssServer.port, self.ssServer.username, self.ssServer.password)
        from connection import create_connection
        self._sock = create_connection((sshost, ssport), self.timeout, parentproxy=self.parentproxy, tunnel=True)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)

    def recv(self, size):
        if not self.connected:
            self.sendall(b'')
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
        if buf_len == 0:
            # Nothing in buffer? Try to read.
            data = self._sock.recv(self.bufsize)
            if not data:
                return b''
            data = self.crypto.decrypt(data)
            if len(data) <= size:
                return data
            buf_len = len(data)
            buf.write(data)
            del data  # explicit free
        buf.seek(0)
        rv = buf.read(size)
        if buf_len > size:
            self._rbuffer.write(buf.read())
        return rv

    def sendall(self, data):
        if self.connected:
            self._sock.sendall(self.crypto.encrypt(data))
        else:
            host, port = self.__address
            self._sock.sendall(self.crypto.encrypt(b''.join([b'\x03',
                                                   chr(len(host)).encode(),
                                                   host.encode(),
                                                   struct.pack(b">H", port),
                                                   data])))
            self.connected = True

    def makefile(self, mode='rb', bufsize=0):
        return self
