#!/usr/bin/env python
# coding:utf-8
import socket
import struct
import encrypt
import errno
import io
import time
import binascii
import hashlib
import logging
logger = logging.getLogger('FW_Lite')
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from parent_proxy import ParentProxy
from dh import DH

method = 'chacha20'
keys = {}


def hex2bytes(data):
    data = '0' * (len(data) % 2) + data
    return binascii.unhexlify(data)


def bytes2hex(data):
    return binascii.hexlify(data).decode()


class hxssocket(object):
    bufsize = 8192

    def __init__(self, hxsServer=None, ctimeout=1, parentproxy=None, iplist=None):
        if hxsServer and not isinstance(hxsServer, ParentProxy):
            hxsServer = ParentProxy(hxsServer, hxsServer)
        self.hxsServer = hxsServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        if self.hxsServer:
            self.PSK = urlparse.parse_qs(self.hxsServer.parse.query).get('PSK', [''])[0]
        self._sock = None
        self.cipher = None
        self.connected = 0
        # value: 0: request not sent
        #        1: request sent, no server response received
        #        2: server response received
        self._rbuffer = io.BytesIO()

    def connect(self, address):
        self.getKey()
        self._address = ('%s:%s' % address).encode()
        self.setsockopt = self._sock.setsockopt
        self.fileno = self._sock.fileno

    def getKey(self):
        from connection import create_connection
        p = self.hxsServer.parse
        host, port, usn, psw = (p.hostname, p.port, p.username, p.password)
        if self.hxsServer.proxy not in keys:
            self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)
            cipher = encrypt.Encryptor(self.PSK, method)
            dh = DH()
            data = chr(0) + struct.pack('>I', int(time.time())) + struct.pack('>H', len(hex2bytes(dh.hexPub))) + hex2bytes(dh.hexPub) + hashlib.sha256(hex2bytes(dh.hexPub) + usn.encode() + psw.encode()).digest()
            self._sock.sendall(cipher.encrypt(data))
            fp = self._sock.makefile('rb')
            resp = ord(cipher.decrypt(fp.read(cipher.iv_len() + 1)))
            if resp == 0:
                pklen = struct.unpack('>H', cipher.decrypt(fp.read(2)))[0]
                pkey = cipher.decrypt(fp.read(pklen))
                auth = cipher.decrypt(fp.read(32))
                if auth == hashlib.sha256(hex2bytes(dh.hexPub) + pkey + usn + psw).digest():
                    shared_secret = dh.genKey(bytes2hex(pkey))
                    keys[self.hxsServer.proxy] = (hashlib.md5(hex2bytes(dh.hexPub)).digest(), shared_secret)
                    return
                raise IOError(0, 'connect to hxsocket server failed! getKey: server auth failed')
            raise IOError(0, 'connect to hxsocket server failed! getKey: bad user')
        else:
            self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)

    def recv(self, size):
        if self.connected == 0:
            self.sendall(b'')
        if self.connected == 1:
            fp = self._sock.makefile('rb')
            if ord(self.cipher.decrypt(fp.read(self.cipher.iv_len() + 1))) != 0:
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
            cipher = encrypt.Encryptor(self.PSK, method)
            self.cipher = encrypt.Encryptor(keys[self.hxsServer.proxy][1], method)
            self._sock.sendall(cipher.encrypt(chr(1) + keys[self.hxsServer.proxy][0]) + self.cipher.encrypt(struct.pack('>I', int(time.time())) + chr(len(self._address)) + self._address + data))
            self.connected = 1
        else:
            self._sock.sendall(self.cipher.encrypt(data))

    def readline(self, size=-1):
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        if buf.tell() > 0:
            # check if we already have it in our buffer
            buf.seek(0)
            bline = buf.readline(size)
            if bline.endswith('\n') or len(bline) == size:
                self._rbuffer = io.BytesIO()
                self._rbuffer.write(buf.read())
                return bline
            del bline
        if size < 0:
            # Read until \n or EOF, whichever comes first
            buf.seek(0, 2)  # seek end
            self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                nl = data.find(b'\n')
                if nl >= 0:
                    nl += 1
                    buf.write(data[:nl])
                    self._rbuffer.write(data[nl:])
                    break
                buf.write(data)
            del data
            return buf.getvalue()
        else:
            # Read until size bytes or \n or EOF seen, whichever comes first
            buf.seek(0, 2)  # seek end
            buf_len = buf.tell()
            if buf_len >= size:
                buf.seek(0)
                rv = buf.read(size)
                self._rbuffer = io.BytesIO()
                self._rbuffer.write(buf.read())
                return rv
            self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                left = size - buf_len
                # did we just receive a newline?
                nl = data.find(b'\n', 0, left)
                if nl >= 0:
                    nl += 1
                    # save the excess data to _rbuf
                    self._rbuffer.write(data[nl:])
                    if buf_len:
                        buf.write(data[:nl])
                        break
                    else:
                        # Shortcut.  Avoid data copy through buf when returning
                        # a substring of our first recv().
                        return data[:nl]
                n = len(data)
                if n == size and not buf_len:
                    # Shortcut.  Avoid data copy through buf when
                    # returning exactly all of our first recv().
                    return data
                if n >= left:
                    buf.write(data[:left])
                    self._rbuffer.write(data[left:])
                    break
                buf.write(data)
                buf_len += n
                # assert buf_len == buf.tell()
            return buf.getvalue()

    def close(self):
        if self._sock:
            self._sock.close()

    def __del__(self):
        self.close()

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
        return new

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

if __name__ == '__main__':
    hxs = hxssocket('hxs://user:pass@127.0.0.1:80')
    hxs.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
