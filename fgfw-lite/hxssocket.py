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
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from parent_proxy import ParentProxy
from dh import DH
keys = {}


def hex2bytes(data):
    data = '0' * (len(data) % 2) + data
    return binascii.unhexlify(data)


def bytes2hex(data):
    return binascii.hexlify(data).decode()


class hxssocket(object):
    bufsize = 8192

    def __init__(self, ssServer=None, ctimeout=1, parentproxy=None, iplist=None):
        if ssServer and not isinstance(ssServer, ParentProxy):
            ssServer = ParentProxy(ssServer, ssServer)
        self.ssServer = ssServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.PSK = urlparse.parse_qs(self.ssServer.parse.query).get('PSK', [''])[0]
        self._sock = None
        self.cipher = None
        self.connected = False
        self._rbuffer = io.BytesIO()

    def connect(self, address):
        self.getKey()
        cipher = encrypt.Encryptor(self.PSK, 'chacha20')
        self.cipher = encrypt.Encryptor(keys[self.ssServer.proxy][1], 'chacha20')
        self._sock.sendall(cipher.encrypt(chr(1) + keys[self.ssServer.proxy][0]))
        netloc = ('%s:%s' % address).encode()
        self._sock.sendall(self.cipher.encrypt(struct.pack('>I', int(time.time())) + chr(len(netloc)) + netloc))
        fp = self._sock.makefile('rb')
        self._sock.settimeout(5)
        if ord(self.cipher.decrypt(fp.read(9))) != 0:
            fp.read(ord(self.cipher.decrypt(fp.read(1))))
            self.getKey()
            cipher = encrypt.Encryptor(self.PSK, 'chacha20')
            self.cipher = encrypt.Encryptor(keys[self.ssServer.proxy][1], 'chacha20')
            self._sock.sendall(cipher.encrypt(chr(1) + keys[self.ssServer.proxy][0]))
            netloc = ('%s:%s' % address).encode()
            self._sock.sendall(self.cipher.encrypt(struct.pack('>I', int(time.time())) + chr(len(netloc)) + netloc))
            fp = self._sock.makefile('rb')
            if ord(self.cipher.decrypt(fp.read(9))) != 0:
                fp.read(ord(self.cipher.decrypt(fp.read(1))))
                raise IOError(0, 'connect to hxsocket server failed! invalid auth.')
        self.connected = True
        self.setsockopt = self._sock.setsockopt
        self.fileno = self._sock.fileno

    def getKey(self):
        if self.ssServer.proxy not in keys:
            p = self.ssServer.parse
            host, port, usn, psw = (p.hostname, p.port, p.username, p.password)
            from connection import create_connection
            self._sock = create_connection((host, port), self.timeout, 5, parentproxy=self.parentproxy, tunnel=True)
            cipher = encrypt.Encryptor(self.PSK, 'chacha20')
            dh = DH()
            data = chr(0) + struct.pack('>I', int(time.time())) + struct.pack('>H', len(hex2bytes(dh.hexPub))) + hex2bytes(dh.hexPub) + hashlib.sha256(hex2bytes(dh.hexPub) + usn.encode() + psw.encode()).digest()
            self._sock.sendall(cipher.encrypt(data))
            fp = self._sock.makefile('rb')
            resp = ord(cipher.decrypt(fp.read(9)))
            if resp == 0:
                pklen = struct.unpack('>H', cipher.decrypt(fp.read(2)))[0]
                pkey = cipher.decrypt(fp.read(pklen))
                auth = cipher.decrypt(fp.read(32))
                if auth == hashlib.sha256(hex2bytes(dh.hexPub) + pkey + usn + psw).digest():
                    shared_secret = dh.genKey(bytes2hex(pkey))
                    keys[self.ssServer.proxy] = (hashlib.md5(hex2bytes(dh.hexPub)).digest(), shared_secret)
                    return
            return 1
        else:
            self._sock = create_connection((host, port), self.timeout, 5, parentproxy=self.parentproxy, tunnel=True)

    def recv(self, size):
        if not self.connected:
            self.sendall(b'')
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
        new.ssServer = self.ssServer
        new.timeout = self.timeout
        new.parentproxy = self.parentproxy
        new._sock = self._sock.dup()
        new.cipher = self.cipher
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
