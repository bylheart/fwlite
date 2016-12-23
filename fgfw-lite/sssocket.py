#!/usr/bin/env python
# coding:utf-8
import struct
import encrypt
import hashlib
import hmac
import io
from parent_proxy import ParentProxy
from basesocket import basesocket


class sssocket(basesocket):
    bufsize = 65519

    def __init__(self, ssServer=None, ctimeout=1, parentproxy=None):
        basesocket.__init__(self)
        if ssServer and not isinstance(ssServer, ParentProxy):
            ssServer = ParentProxy(ssServer, ssServer)
        self.ssServer = ssServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.crypto = None
        self.__ota = False
        self._ota_chunk_idx = 0
        self.connected = False

    def connect(self, address):
        self.__address = address
        sshost, ssport, ssmethod, sspassword = (self.ssServer.hostname, self.ssServer.port, self.ssServer.username.lower(), self.ssServer.password)
        from connection import create_connection
        if ssmethod.endswith('-auth'):
            self.__ota = True
            ssmethod = ssmethod[:-5]
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
            if self.__ota:
                # modified from https://github.com/shadowsocks/shadowsocks/blob/master/shadowsocks/tcprelay.py
                data_len = struct.pack(">H", len(data))
                index = struct.pack('>I', self._ota_chunk_idx)
                key = self.crypto.cipher_iv + index
                sha110 = hmac.new(key, data, hashlib.sha1).digest()[:10]
                self._ota_chunk_idx += 1
                data = data_len + sha110 + data
            self._sock.sendall(self.crypto.encrypt(data))
        else:
            # https://shadowsocks.org/en/spec/one-time-auth.html
            host, port = self.__address
            addrtype = 19 if self.__ota else 3
            header = b''.join([chr(addrtype).encode(),
                               chr(len(host)).encode(),
                               host.encode(),
                               struct.pack(b">H", port)])
            if self.__ota:
                key = self.crypto.cipher_iv + self.crypto.key
                header += hmac.new(key, header, hashlib.sha1).digest()[:10]
            self._sock.sendall(self.crypto.encrypt(header))
            self.connected = True
            if data:
                self.sendall(data)

    def makefile(self, mode='rb', bufsize=0):
        return self

if __name__ == '__main__':
    s = sssocket('ss://aes-128-cfb:password@127.0.0.1:8138', 5)
    s.connect(('www.baidu.com', 80))
    s.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = s.recv(1024)
    while data:
        print(repr(data))
        data = s.recv(1024)
