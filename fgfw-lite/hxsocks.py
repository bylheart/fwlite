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

from builtins import chr

import os
import struct
import io
import time
import random
import hashlib
import hmac
import traceback
import select
import socket
import backports.socketpair
from six import byte2int

from collections import defaultdict
from threading import RLock, Thread
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
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


DEFAULT_METHOD = 'aes-128-cfb'
DEFAULT_HASH = 'sha256'
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
        result[0].settimeout(ctimeout)
        return result[0]
    return _hxssocket(hxsServer, ctimeout, parentproxy)


class _hxssocket(object):
    bufsize = 8192

    def __init__(self, hxsServer, ctimeout=4, parentproxy=None):
        if not isinstance(hxsServer, ParentProxy):
            hxsServer = ParentProxy(hxsServer, hxsServer)
        self.hxsServer = hxsServer
        self.timeout = ctimeout
        self._sock = None
        self._socketpair_a, self._socketpair_b = socket.socketpair()
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
            self._rfile = self._sock.makefile('rb')
            self._header_sent = False
            self._header_received = False
        logger.debug('hxsocks send connect request')
        padding_len = random.randint(64, 255)
        pt = b''.join([struct.pack('>I', int(time.time())),
                       chr(len(self._address[0])).encode('latin1'),
                       self._address[0].encode(),
                       struct.pack('>H', self._address[1]),
                       b'\x00' * padding_len])
        ct = self.cipher.encrypt(pt)
        self._sock.sendall(self.pskcipher.encrypt(b''.join([chr(11).encode(),
                                                            keys[self.serverid][0],
                                                            struct.pack('>H', len(ct))])) + ct)

        resp_len = 2 if self.pskcipher.decipher else self.pskcipher.iv_len + 2
        data = self._rfile.read(resp_len)
        if not data:
            raise IOError(0, 'hxsocks Error: connection closed.')
        resp_len = self.pskcipher.decrypt(data)
        resp_len = struct.unpack('>H', resp_len)[0]

        ct = self._rfile.read(resp_len)

        try:
            resp = self.cipher.decrypt(ct)
        except ValueError:
            if self.serverid in keys:
                del keys[self.serverid]
            raise IOError(0, 'hxsocks Error: invalid shared key.')

        d = byte2int(resp) if resp else None
        if d == 0:
            logger.debug('hxsocks connected')
            self.readable = 1
            self.writeable = 1
            # start forwarding
            self._thread = Thread(target=self.forward_tcp, args=(self._socketpair_b, self._sock, self.cipher, self.pskcipher, 60))
            self._thread.start()
        else:
            raise IOError(0, 'hxsocks Error: remote connect failed. code %d' % d)

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
                        self._rfile = self._sock.makefile('rb')
                        self._header_sent = False
                        self._header_received = False
                    acipher = ECC(self.pskcipher.key_len)
                    pubk = acipher.get_pub_key()
                    logger.debug('hxsocks send key exchange request')
                    ts = struct.pack('>I', int(time.time()))
                    padding_len = random.randint(64, 255)
                    data = b''.join([ts,
                                     chr(len(pubk)).encode('latin1'),
                                     pubk,
                                     hmac.new(psw.encode(), ts + pubk + usn.encode(), hashlib.sha256).digest(),
                                     b'\x00' * padding_len])
                    data = chr(10).encode() + struct.pack('>H', len(data)) + data
                    self._sock.sendall(self.pskcipher.encrypt(data))
                    resp_len = 2 if self.pskcipher.decipher else self.pskcipher.iv_len + 2
                    resp_len = self.pskcipher.decrypt(self._rfile.read(resp_len))
                    resp_len = struct.unpack('>H', resp_len)[0]
                    data = self.pskcipher.decrypt(self._rfile.read(resp_len))

                    data = io.BytesIO(data)

                    resp_code = byte2int(data.read(1))
                    if resp_code == 0:
                        logger.debug('hxsocks read key exchange respond')
                        pklen = byte2int(data.read(1))
                        scertlen = byte2int(data.read(1))
                        siglen = byte2int(data.read(1))

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
                                self.cipher = encrypt.AEncryptor(keys[self.serverid][1], self.method, CTX)
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
                self.cipher = encrypt.AEncryptor(keys[self.serverid][1], self.method, CTX)

    def forward_tcp(self, local, remote, cipher, pskcipher, timeout=60):
        # local: self._socketpair_b, connect with client
        # remote: self._sock, connect with server
        fds = [local, remote]
        total_send = 0
        try:
            while fds:
                if len(fds) < 2:
                    timeout = 10
                ins, _, _ = select.select(fds, [], [], timeout)
                if not ins:
                    logger.debug('timed out')
                    break
                if remote in ins:
                    ct_len = self._rfile.read(2)
                    if not ct_len:
                        logger.debug('server closed')
                        fds.remove(remote)
                        local.shutdown(socket.SHUT_WR)
                        break
                    ct_len = struct.unpack('>H', pskcipher.decrypt(ct_len))[0]
                    ct = self._rfile.read(ct_len)
                    data = cipher.decrypt(ct)
                    pad_len = ord(data[0])
                    cmd = ord(data[-1])
                    if 0 < pad_len < 8:
                        logger.debug('Fake chunk, drop')
                        if pad_len == 1:
                            logger.debug('sending fake chunk')
                            self.send_fake_chunk(2)
                    else:
                        data = data[1:0-pad_len] if pad_len else data[1:]
                        if data:
                            local.sendall(data)
                        else:
                            logger.debug('server close, gracefully')
                            if cmd:
                                local.close()
                            else:
                                local.shutdown(socket.SHUT_WR)
                            fds.remove(remote)
                            self.readable = 0

                if local in ins:
                    data = local.recv(self.bufsize)
                    if not data:
                        fds.remove(local)
                        if total_send < 8196 and random.random() < 0.5:
                            _data = chr(2).encode('latin1') + b'\x00' * random.randint(1024, 8196)
                            ct = cipher.encrypt(_data)
                            _data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
                            remote.sendall(_data)
                        self.writeable = 0
                    total_send += len(data)
                    padding_len = random.randint(8, 255)
                    data = chr(padding_len).encode('latin1') + data + b'\x00' * padding_len
                    ct = cipher.encrypt(data)
                    data = pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
                    remote.sendall(data)
        except socket.timeout:
            pass
        except (OSError, IOError) as e:
            if e.args[0] in (errno.EBADF,):
                return
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        except Exception as e:
            logger.error(repr(e))
            logger.error(traceback.format_exc())
        finally:
            try:
                local.close()
            except (OSError, IOError):
                pass
        remote.close()

    def send_fake_chunk(self, flag):
        # if flag == 1, other side should respond a fake chunk
        assert 0 < flag < 8
        if flag == 1:
            logger.warning('hxsocks client requesting fake chunk could cause trouble')
        data = chr(flag).encode('latin1') + b'\x00' * random.randint(64, 512)
        ct = self.cipher.encrypt(data)
        data = self.pskcipher.encrypt(struct.pack('>H', len(ct))) + ct
        self._sock.sendall(data)

    def close(self):
        logger.debug('hxsocks close, readable %s, writeable %s' % (self.readable, self.writeable))
        if self.pooled:
            try:
                self._rfile.close()
                self._sock.close()
            except Exception:
                pass
            return

    def recv(self, size):
        return self._socketpair_a.recv(size)

    def sendall(self, data):
        return self._socketpair_a.sendall(data)

    def makefile(self, mode='rb', bufsize=0):
        return self._socketpair_a.makefile(mode, bufsize)

    def settimeout(self, value):
        self._socketpair_a.settimeout(value)
        self._sock.settimeout(value)

    def setsockopt(self, level, optname, value):
        return self._socketpair_a.setsockopt(level, optname, value)

    def fileno(self):
        return self._socketpair_a.fileno()

    def shutdown(self, how):
        return self._socketpair_a.shutdown(how)

    def close(self):
        return self._socketpair_a.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    hxs = hxssocket('hxs://user:pass@127.0.0.1:8138/?PSK=password&method=aes-128-cfb&obfs=http')
    hxs.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
