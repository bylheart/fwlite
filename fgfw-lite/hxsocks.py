#!/usr/bin/env python
# coding:utf-8
#
# Copyright (C) 2014 - 2015 Jiang Chao <sgzz.cj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses>.

import os
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
from ecc import ECC

default_method = 'rc4-md5'
keys = {}
newkey_lock = defaultdict(RLock)
salt = b'G\x91V\x14{\x00\xd9xr\x9d6\x99\x81GL\xe6c>\xa9\\\xd2\xc6\xe0:\x9c\x0b\xefK\xd4\x9ccU'
ctx = b'hxsocks'
mac_len = 16
known_hosts = {}
# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        known_hosts[fname[:-5]] = open('./.hxs_known_hosts/' + fname).read()


class hxssocket(basesocket):
    bufsize = 32768

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
            self.serverid = (self.hxsServer.parse.username, self.hxsServer.parse.hostname)
            self.uphash = hashlib.sha256(self.hxsServer.parse.username.encode() + self.hxsServer.parse.password.encode()).digest()
        self.cipher = None
        self.connected = 0
        self._data_bak = None
        # value: 0: request not sent
        #        1: request sent, no server response received
        #        2: server response received

    def connect(self, address):
        self._address = ('%s:%s' % address).encode()
        self._connect()

    def _connect(self):
        self.connected = 0
        self.getKey()
        if self._sock is None:
            from connection import create_connection
            p = self.hxsServer.parse
            host, port = p.hostname, p.port
            self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)
            self.pskcipher = encrypt.Encryptor(self.PSK, self.method)

    def getKey(self):
        with newkey_lock[self.serverid]:
            if self.serverid not in keys:
                for _ in range(2):
                    logger.debug('hxsocks getKey')
                    p = self.hxsServer.parse
                    host, port, usn, psw = (p.hostname, p.port, p.username, p.password)
                    if self._sock is None:
                        logger.debug('hxsocks connect')
                        from connection import create_connection
                        self._sock = create_connection((host, port), self.timeout, self.timeout + 2, parentproxy=self.parentproxy, tunnel=True)
                        self.pskcipher = encrypt.Encryptor(self.PSK, self.method)
                    acipher = ECC(self.pskcipher.key_len)
                    pubk = acipher.get_pub_key()
                    logger.debug('hxsocks send key exchange request')
                    data = chr(0) + struct.pack('>I', int(time.time())) + chr(len(pubk)) + pubk + hashlib.sha256(pubk + usn.encode() + psw.encode()).digest()
                    self._sock.sendall(self.pskcipher.encrypt(data))
                    fp = self._sock.makefile('rb', 0)
                    resp_len = 1 if self.pskcipher.decipher else self.pskcipher.iv_len + 1
                    resp = ord(self.pskcipher.decrypt(fp.read(resp_len)))
                    if resp == 0:
                        logger.debug('hxsocks read key exchange respond')
                        pklen = ord(self.pskcipher.decrypt(fp.read(1)))
                        server_key = self.pskcipher.decrypt(fp.read(pklen))
                        auth = self.pskcipher.decrypt(fp.read(32))
                        pklen = ord(self.pskcipher.decrypt(fp.read(1)))
                        server_cert = self.pskcipher.decrypt(fp.read(pklen))
                        rlen = ord(self.pskcipher.decrypt(fp.read(1)))
                        r = self.pskcipher.decrypt(fp.read(rlen))
                        s = self.pskcipher.decrypt(fp.read(rlen))
                        # TODO: ask user if a certificate should be accepted or not.
                        if host not in known_hosts:
                            logger.info('hxs: server %s new cert %s saved.' % (host, hashlib.sha256(server_cert).hexdigest()[:8]))
                            with open('./.hxs_known_hosts/' + host + '.cert', 'wb') as f:
                                f.write(server_cert)
                                known_hosts[host] = server_cert
                        elif known_hosts[host] != server_cert:
                            logger.error('hxs: server %s certificate mismatch! PLEASE CHECK!')
                            raise OSError(0, 'hxs: bad certificate')
                        if auth == hashlib.sha256(pubk + server_key + usn + psw).digest():
                            if ECC.verify_with_pub_key(server_cert, auth, r, s):
                                shared_secret = acipher.get_dh_key(server_key)
                                keys[self.serverid] = (hashlib.md5(pubk).digest(), shared_secret)
                                logger.debug('hxsocks key exchange success')
                                return
                            else:
                                logger.error('hxsocket getKey Error: server auth failed, bad signature')
                        else:
                            logger.error('hxsocket getKey Error: server auth failed, bad username or password')
                    else:
                        fp.read(ord(self.pskcipher.decrypt(fp.read(1))))
                        logger.error('hxsocket getKey Error. bad password or timestamp.')

    def recv(self, size):
        if self.connected == 0:
            self.sendall(b'')
        if self.connected == 1:
            for i in range(2):
                fp = self._sock.makefile('rb', 0)
                resp_len = 1 if self.pskcipher.decipher else self.pskcipher.iv_len + 1
                # now don't need to worry pskcipher iv anymore.
                logger.debug('resp_len: %d' % resp_len)
                data = fp.read(resp_len)
                d = ord(self.pskcipher.decrypt(data)) if data else None
                if d == 0:
                    break
                else:
                    if self.serverid in keys:
                        del keys[self.serverid]
                    if i:
                        logger.error('hxsocket Error: invalid shared key.')
                        return b''
                    logger.debug('hxsocket Error: invalid shared key. try again.')
                    if d is None:
                        self._sock = None
                    else:
                        fp.read(ord(self.pskcipher.decrypt(fp.read(1))))
                    self._connect()
                    self.sendall(self._data_bak or b'')
            fp.read(ord(self.pskcipher.decrypt(fp.read(1))))
            self.connected = 2
        fp = self._sock.makefile('rb', 0)
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
        if buf_len == 0:
            # Nothing in buffer? Try to read.
            ctlen = fp.read(2)
            if not ctlen:
                return b''
            ctlen = struct.unpack('>H', self.pskcipher.decrypt(ctlen))[0]
            ct = fp.read(ctlen)
            mac = fp.read(mac_len)
            data = self.cipher.decrypt(ct, mac)
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
        if self.connected == 0:
            logger.debug('hxsocks send connect request')
            self.cipher = encrypt.AEncryptor(keys[self.serverid][1], self.method, salt, ctx, 0)

            pt = struct.pack('>I', int(time.time())) + self.uphash + chr(len(self._address)) + self._address + data
            ct, mac = self.cipher.encrypt(pt)
            self._sock.sendall(self.pskcipher.encrypt(chr(1) + keys[self.serverid][0] + struct.pack('>H', len(ct))) + ct + mac)
            if data and self._data_bak is None:
                self._data_bak = data
            self.connected = 1
        else:
            ct, mac = self.cipher.encrypt(data)
            self._sock.sendall(self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac)

if __name__ == '__main__':
    hxs = hxssocket('hxs://user:pass@127.0.0.1:80')
    hxs.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
