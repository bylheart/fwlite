#!/usr/bin/env python
# coding:utf-8
import struct
import encrypt
import io
import time
import hashlib
import logging
logger = logging.getLogger('FW_Lite')
from collections import defaultdict
from threading import RLock
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from basesocket import basesocket
from parent_proxy import ParentProxy
from dh import DH

default_method = 'rc4-md5'
keys = {}
newkey_lock = defaultdict(RLock)


class hxssocket(basesocket):
    bufsize = 8192

    def __init__(self, hxsServer=None, ctimeout=1, parentproxy=None, iplist=None):
        basesocket.__init__(self)
        if hxsServer and not isinstance(hxsServer, ParentProxy):
            hxsServer = ParentProxy(hxsServer, hxsServer)
        self.hxsServer = hxsServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        if self.hxsServer:
            self.PSK = urlparse.parse_qs(self.hxsServer.parse.query).get('PSK', [''])[0]
            self.method = urlparse.parse_qs(self.hxsServer.parse.query).get('method', [''])[0] or default_method
        self.cipher = None
        self.connected = 0
        # value: 0: request not sent
        #        1: request sent, no server response received
        #        2: server response received

    def connect(self, address):
        self.getKey()
        if self._sock is None:
            from connection import create_connection
            p = self.hxsServer.parse
            host, port = p.hostname, p.port
            self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)
        self._address = ('%s:%s' % address).encode()
        self.setsockopt = self._sock.setsockopt
        self.fileno = self._sock.fileno

    def getKey(self):
        from connection import create_connection
        with newkey_lock[self.hxsServer]:
            if self.hxsServer.proxy not in keys:
                p = self.hxsServer.parse
                host, port, usn, psw = (p.hostname, p.port, p.username, p.password)
                self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)
                cipher = encrypt.Encryptor(self.PSK, self.method)
                dh = DH()
                pubk = dh.getPubKey()
                data = chr(0) + struct.pack('>I', int(time.time())) + struct.pack('>H', len(pubk)) + pubk + hashlib.sha256(pubk + usn.encode() + psw.encode()).digest()
                self._sock.sendall(cipher.encrypt(data))
                fp = self._sock.makefile('rb')
                resp = ord(cipher.decrypt(fp.read(cipher.iv_len + 1)))
                if resp == 0:
                    pklen = struct.unpack('>H', cipher.decrypt(fp.read(2)))[0]
                    pkey = cipher.decrypt(fp.read(pklen))
                    auth = cipher.decrypt(fp.read(32))
                    if auth == hashlib.sha256(pubk + pkey + usn + psw).digest():
                        shared_secret = dh.genKey(pkey)
                        keys[self.hxsServer.proxy] = (hashlib.md5(pubk).digest(), shared_secret)
                        return
                    raise IOError(0, 'connect to hxsocket server failed! getKey: server auth failed')
                raise IOError(0, 'connect to hxsocket server failed! getKey: bad user')

    def recv(self, size):
        if self.connected == 0:
            self.sendall(b'')
        if self.connected == 1:
            fp = self._sock.makefile('rb')
            if ord(self.cipher.decrypt(fp.read(self.cipher.iv_len + 1))) != 0:
                fp.read(ord(self.cipher.decrypt(fp.read(1))))
                del keys[self.hxsServer.proxy]
                logger.error('connect to hxsocket server failed! invalid shared key.')
                # TODO: it is possible to reconnect here.
                return b''
            self.connected = 2
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
        if buf_len < size:
            # Not enough data in buffer?  Try to read.
            data = self.cipher.decrypt(self._sock.recv(size - buf_len))
            if len(data) == size and not buf_len:
                # Shortcut.  Avoid buffer data copies
                return data
            buf.write(data)
            del data  # explicit free
        buf.seek(0)
        rv = buf.read(size)
        self._rbuffer.write(buf.read())
        return rv

    def sendall(self, data):
        if self.connected == 0:
            cipher = encrypt.Encryptor(self.PSK, self.method)
            self.cipher = encrypt.Encryptor(keys[self.hxsServer.proxy][1], self.method)
            self._sock.sendall(cipher.encrypt(chr(1) + keys[self.hxsServer.proxy][0]) + self.cipher.encrypt(struct.pack('>I', int(time.time())) + chr(len(self._address)) + self._address + data))
            self.connected = 1
        else:
            self._sock.sendall(self.cipher.encrypt(data))

    def dup(self):
        new = hxssocket()
        new.hxsServer = self.hxsServer
        new.timeout = self.timeout
        new.parentproxy = self.parentproxy
        new._sock = self._sock.dup()
        new.cipher = self.cipher
        new.PSK = self.PSK
        new.connected = self.connected
        new._rbuffer = self._rbuffer
        new.method = self.method
        return new

if __name__ == '__main__':
    hxs = hxssocket('hxs://user:pass@127.0.0.1:80')
    hxs.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
