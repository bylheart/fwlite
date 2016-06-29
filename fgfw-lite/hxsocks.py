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
import io
import time
import random
import hashlib
import hmac
import socket

from collections import defaultdict
from threading import RLock, Thread
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from basesocket import basesocket
from parent_proxy import ParentProxy
from httputil import httpconn_pool
import encrypt
from ecc import ECC

import logging

logger = logging.getLogger('hxsocks')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


DEFAULT_METHOD = 'rc4-md5'
DEFAULT_HASH = 'sha256'
SALT = b'G\x91V\x14{\x00\xd9xr\x9d6\x99\x81GL\xe6c>\xa9\\\xd2\xc6\xe0:\x9c\x0b\xefK\xd4\x9ccU'
CTX = b'hxsocks'
MAC_LEN = 16

keys = {}
newkey_lock = defaultdict(RLock)
known_hosts = {}

# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        known_hosts[fname[:-5]] = open('./.hxs_known_hosts/' + fname, 'rb').read()


POOL = httpconn_pool()


def hxssocket(hxsServer, ctimeout=4, parentproxy=None):
    if not isinstance(hxsServer, ParentProxy):
        hxsServer = ParentProxy(hxsServer, hxsServer)
    result = POOL.get(hxsServer.parse.hostname)
    if result:
        logger.debug('hxsocks reusing connection, ' + result[1])
        result[0].pooled = 0
        return result[0]
    return _hxssocket(hxsServer, ctimeout, parentproxy)


class _hxssocket(basesocket):
    bufsize = 8192

    def __init__(self, hxsServer, ctimeout=4, parentproxy=None):
        basesocket.__init__(self)
        if not isinstance(hxsServer, ParentProxy):
            hxsServer = ParentProxy(hxsServer, hxsServer)
        self.hxsServer = hxsServer
        self.timeout = ctimeout
        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        self.PSK = urlparse.parse_qs(self.hxsServer.parse.query).get('PSK', [''])[0]
        self.method = urlparse.parse_qs(self.hxsServer.parse.query).get('method', [DEFAULT_METHOD])[0].lower()
        self.hash_algo = urlparse.parse_qs(self.hxsServer.parse.query).get('hash', [DEFAULT_HASH])[0].upper()
        self.serverid = (self.hxsServer.username, self.hxsServer.hostname)
        self.cipher = None
        self._data_bak = None
        self.readable = 0
        self.writeable = 0
        self.pooled = 0

    def connect(self, address):
        self._address = address
        self.getKey()
        if self._sock is None:
            from connection import create_connection
            host, port = self.hxsServer.hostname, self.hxsServer.port
            self._sock = create_connection((host, port), self.timeout, parentproxy=self.parentproxy, tunnel=True)
            self.pskcipher = encrypt.Encryptor(self.PSK, self.method)
        logger.debug('hxsocks send connect request')
        padding_len = random.randint(64, 255)
        pt = struct.pack('>I', int(time.time())) + chr(len(self._address[0])) + self._address[0] + struct.pack('>H', self._address[1]) + b'\x00' * padding_len
        ct, mac = self.cipher.encrypt(pt)
        self._sock.sendall(self.pskcipher.encrypt(chr(11) + keys[self.serverid][0] + struct.pack('>H', len(ct))) + ct + mac)

        fp = self._sock.makefile('rb', 0)
        resp_len = 2 if self.pskcipher.decipher else self.pskcipher.iv_len + 2
        resp_len = self.pskcipher.decrypt(fp.read(resp_len))
        resp_len = struct.unpack('>H', resp_len)[0]

        resp = self.pskcipher.decrypt(fp.read(resp_len))

        d = ord(resp[0]) if resp else None
        if d == 0:
            logger.debug('hxsocks connected')
            self.readable = 1
            self.writeable = 1
            return
        elif d == 2:
            raise IOError(0, 'hxsocket Error: remote connect timed out. code 2')
        else:
            if self.serverid in keys:
                del keys[self.serverid]
            raise IOError(0, 'hxsocket Error: invalid shared key. code %d' % d)

    def getKey(self):
        with newkey_lock[self.serverid]:
            if self.serverid not in keys:
                for _ in range(2):
                    logger.debug('hxsocks getKey')
                    host, port, usn, psw = (self.hxsServer.hostname, self.hxsServer.port, self.hxsServer.username, self.hxsServer.password)
                    if self._sock is None:
                        logger.debug('hxsocks connect')
                        from connection import create_connection
                        self._sock = create_connection((host, port), self.timeout, parentproxy=self.parentproxy, tunnel=True)
                        self.pskcipher = encrypt.Encryptor(self.PSK, self.method)
                    acipher = ECC(self.pskcipher.key_len)
                    pubk = acipher.get_pub_key()
                    logger.debug('hxsocks send key exchange request')
                    ts = struct.pack('>I', int(time.time()))
                    padding_len = random.randint(64, 255)
                    data = ts + chr(len(pubk)) + pubk + hmac.new(psw.encode(), ts + pubk + usn.encode(), hashlib.sha256).digest()\
                        + b'\x00' * padding_len
                    data = chr(10) + struct.pack('>H', len(data)) + data
                    self._sock.sendall(self.pskcipher.encrypt(data))
                    fp = self._sock.makefile('rb', 0)
                    resp_len = 2 if self.pskcipher.decipher else self.pskcipher.iv_len + 2
                    resp_len = self.pskcipher.decrypt(fp.read(resp_len))
                    resp_len = struct.unpack('>H', resp_len)[0]
                    data = self.pskcipher.decrypt(fp.read(resp_len))

                    data = io.BytesIO(data)

                    resp_code = ord(data.read(1))
                    if resp_code == 0:
                        logger.debug('hxsocks read key exchange respond')
                        pklen = ord(data.read(1))
                        scertlen = ord(data.read(1))
                        siglen = ord(data.read(1))

                        server_key = data.read(pklen)
                        auth = data.read(32)
                        server_cert = data.read(scertlen)
                        signature = data.read(siglen)

                        # TODO: ask user if a certificate should be accepted or not.
                        if host not in known_hosts:
                            logger.info('hxs: server %s new cert %s saved.' % (host, hashlib.sha256(server_cert).hexdigest()[:8]))
                            with open('./.hxs_known_hosts/' + host + '.cert', 'wb') as f:
                                f.write(server_cert)
                                known_hosts[host] = server_cert
                        elif known_hosts[host] != server_cert:
                            logger.error('hxs: server %s certificate mismatch! PLEASE CHECK!' % host)
                            raise OSError(0, 'hxs: bad certificate')
                        if auth == hmac.new(psw.encode(), pubk + server_key + usn.encode(), hashlib.sha256).digest():
                            if ECC.verify_with_pub_key(server_cert, auth, signature, self.hash_algo):
                                shared_secret = acipher.get_dh_key(server_key)
                                keys[self.serverid] = (hashlib.md5(pubk).digest(), shared_secret)
                                self.cipher = encrypt.AEncryptor(keys[self.serverid][1], self.method, SALT, CTX, 0, MAC_LEN)
                                logger.debug('hxs key exchange success')
                                return
                            else:
                                logger.error('hxs getKey Error: server auth failed, bad signature')
                        else:
                            logger.error('hxs getKey Error: server auth failed, bad username or password')
                    else:
                        logger.error('hxs getKey Error. bad password or timestamp.')
                else:
                    raise IOError(0, 'hxs getKey Error')
            else:
                self.cipher = encrypt.AEncryptor(keys[self.serverid][1], self.method, SALT, CTX, 0, MAC_LEN)

    def recv(self, size):
        logger.debug('hxsocks recv')
        # if not self.readable:
        #     return b''
        fp = self._sock.makefile('rb', 0)
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
        if buf_len == 0:
            logger.debug('Nothing in buffer. Try to read.')
            while 1:
                ctlen = fp.read(2)
                if not ctlen:
                    return b''
                ctlen = struct.unpack('>H', self.pskcipher.decrypt(ctlen))[0]
                ct = fp.read(ctlen)
                mac = fp.read(MAC_LEN)
                data = self.cipher.decrypt(ct, mac)
                pad_len = ord(data[0])
                if 0 < pad_len < 8:
                    logger.debug('Fake chunk, drop')
                    if pad_len == 1:
                        logger.debug('sending fake chunk')
                        self.send_fake_chunk(2)
                    # server should be sending another chunk right away
                    continue
                data = data[1:0-pad_len] if ord(data[0]) else data[1:]
                if not data:
                    logger.debug('hxsocks recv closed gracefully')
                    self.readable = 0
                    return b''
                if len(data) <= size:
                    return data
                buf_len = len(data)
                buf.write(data)
                del data  # explicit free
                break
        buf.seek(0)
        rv = buf.read(size)
        if buf_len > size:
            self._rbuffer.write(buf.read())
        return rv

    def send_fake_chunk(self, flag):
        # if flag == 1, other side should respond a fake chunk
        assert 0 < flag < 8
        if flag == 1:
            logger.warning('hxsocks client requesting fake chunk could cause trouble')
        data = chr(flag) + b'\x00' * random.randint(64, 512)
        ct, mac = self.cipher.encrypt(data)
        data = self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
        self._sock.sendall(data)

    def sendall(self, data):
        if not data:
            logger.warning('no data!!!')
        logger.debug('hxsocks send data')
        data_more = None
        if len(data) > self.bufsize:
            data, data_more = data[:self.bufsize], data[self.bufsize:]
        padding_len = random.randint(8, 255)
        padding = b'\x00' * padding_len
        data = chr(padding_len) + data + padding

        ct, mac = self.cipher.encrypt(data)
        data = self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
        self._sock.sendall(data)
        if data_more:
            self.sendall(data_more)
        logger.debug('hxsocks send data completed')

    def makefile(self, mode='rb', bufsize=0):
        return self

    def shutdown(self, how):
        if how == socket.SHUT_WR:
            logger.debug('hxsocks shutdown write')
            padding_len = random.randint(8, 255)
            data = chr(padding_len) + b'\x00' * padding_len

            ct, mac = self.cipher.encrypt(data)
            data = self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
            self._sock.sendall(data)
            self.writeable = 0

    def close(self):
        logger.debug('hxsocks close, readable %s, writeable %s' % (self.readable, self.writeable))
        if self.pooled:
            try:
                self._sock.close()
            except Exception:
                pass
            return
        if self.writeable:
            logger.debug('hxsocks shutdown write, close')
            padding_len = random.randint(8, 255)
            data = chr(padding_len) + b'\x01' * padding_len

            ct, mac = self.cipher.encrypt(data)
            data = self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct + mac
            self._sock.sendall(data)
            self.writeable = 0
        if self.readable:
            t = Thread(target=self._wait_close)
            t.daemon = True
            t.start()
        logger.debug('hxsocks add to pool')
        self.pooled = 1
        POOL.put(self.hxsServer.parse.hostname, self, self.hxsServer.name)

    def _wait_close(self):
        logger.debug('hxsocks _wait_close')
        self.settimeout(8)
        while 1:
            try:
                fp = self._sock.makefile('rb', 0)
                ctlen = fp.read(2)
                if not ctlen:
                    raise IOError(0, '')
                ctlen = struct.unpack('>H', self.pskcipher.decrypt(ctlen))[0]
                ct = fp.read(ctlen)
                mac = fp.read(MAC_LEN)
                data = self.cipher.decrypt(ct, mac)
                pad_len = ord(data[0])
                if 0 < pad_len < 8:
                    # fake chunk, drop
                    if pad_len == 1:
                        self.send_fake_chunk(2)
                    # server should be sending another chunk right away
                    continue
                data = data[1:0-pad_len] if ord(data[0]) else data[1:]
                if not data:
                    logger.debug('hxsocks add to pool')
                    self.pooled = 1
                    POOL.put(self.hxsServer.parse.hostname, self, self.hxsServer.name)
                    self.readable = 0
                    break
            except Exception:
                self._sock.close()
                return


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    hxs = hxssocket('hxs://user:pass@127.0.0.1:9000')
    hxs.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
