#!/usr/bin/env python
# coding:utf-8
#
# Copyright (C) 2018 Jiang Chao <sgzz.cj@gmail.com>
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
from six import byte2int, indexbytes

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

from threading import RLock, Thread, Event
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse
from parent_proxy import ParentProxy
import encrypt
from encrypt import InvalidTag, AEncryptor, Encryptor
from ecc import ECC, InvalidSignature

import logging

logger = logging.getLogger('hxsocks2')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

if not hasattr(socket, 'socketpair'):
    import backports.socketpair


DEFAULT_METHOD = 'aes-128-cfb'
DEFAULT_HASH = 'sha256'
CTX = b'hxsocks2'
MAX_STREAM_ID = 65530

OPEN = 0
LOCAL_CLOSED = 1   # SENT END_STREAM
REMOTE_CLOSED = 2  # RECV END_STREAM
CLOSED = 3
END_STREAM_FLAG = 1
known_hosts = {}

# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        known_hosts[fname[:-5]] = open('./.hxs_known_hosts/' + fname, 'rb').read()

CONN_MANAGER = {}  # (server, parentproxy): manager


class conn_manager(object):
    def __init__(self, ctimeout):
        self.ctimeout = ctimeout
        self.connection = None

    def get_connection(self, hxsServer, parentproxy):
        # choose / create and return a connection
        if not self.connection:
            self.connection = hxs2_connection(hxsServer, self.ctimeout, parentproxy, self)
        return self.connection

    def remove(self, conn):
        # this connection is not accepting new streams anymore
        if conn is self.connection:
            self.connection = None


def hxs2_get_connection(hxsServer, ctimeout, parentproxy=None):
    id_ = urlparse.parse_qs(hxsServer.parse.query).get('id', [hxsServer.name, ])[0]
    if id_ not in CONN_MANAGER:
        CONN_MANAGER[id_] = conn_manager(ctimeout)
    return CONN_MANAGER[id_].get_connection(hxsServer, parentproxy)


class hxs2_connection(object):
    bufsize = 8192

    def __init__(self, hxsServer, ctimeout, parentproxy, manager):
        if not isinstance(hxsServer, ParentProxy):
            hxsServer = ParentProxy(hxsServer, hxsServer)
        self.hxsServer = hxsServer
        self.name = self.hxsServer.name
        self.timeout = ctimeout
        self._manager = manager
        self._last_ping = 0

        self._sock = None
        self._rfile = None

        if parentproxy and not isinstance(parentproxy, ParentProxy):
            parentproxy = ParentProxy(parentproxy, parentproxy)
        self.parentproxy = parentproxy
        _psk = urlparse.parse_qs(self.hxsServer.parse.query).get('PSK', [''])[0]
        self.method = urlparse.parse_qs(self.hxsServer.parse.query).get('method', [DEFAULT_METHOD])[0].lower()
        self.hash_algo = urlparse.parse_qs(self.hxsServer.parse.query).get('hash', [DEFAULT_HASH])[0].upper()

        self._connection_write_lock = RLock()

        self.__pskcipher = Encryptor(_psk, self.method)
        self.__cipher = None
        self._next_stream_id = 1

        self._client_sock = {}
        self._client_status = {}
        self._stream_status = {}

        try:
            self.getKey()
        except Exception as e:
            for item in (self._rfile, self._sock):
                try:
                    item.close()
                except Exception:
                    pass
            raise e
        # start read from hxsocks2 connection
        Thread(target=self.read_from_connection).start()

    def connect(self, address, timeout=3):
        logger.debug('hxsocks2 send connect request')
        payload = b''.join([chr(len(address[0])).encode('latin1'),
                            address[0].encode(),
                            struct.pack('>H', address[1]),
                            b'\x00' * random.randint(64, 255),
                            ])
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        if self._next_stream_id > MAX_STREAM_ID:
            logger.info('MAX_STREAM_ID reached')
            self._manager.remove(self)

        self.send_frame(1, 0, stream_id, payload)
        # wait for server response
        event = Event()
        self._client_status[stream_id] = event
        event.wait(timeout=timeout)

        if stream_id not in self._stream_status:
            # server should have some response by now
            logger.error('not connected from %s, timeout=%.3f' % (self.name, timeout))
            self.send_ping()
            # self._manager.remove(self)
            raise OSError('not connected')

        if self._stream_status[stream_id] == OPEN:
            socketpair_a, socketpair_b = socket.socketpair()
            socketpair_a.settimeout(5)
            socketpair_b.settimeout(5)
            self._client_status[stream_id] = OPEN
            self._client_sock[stream_id] = socketpair_b
            # TODO: start forwarding
            Thread(target=self.read_from_client, args=(stream_id, )).start()
            return socketpair_a
        else:
            raise OSError('connect to %s failed.' % ('%s:%d' % address))

    def read_from_client(self, stream_id):
        logger.debug('start read from client')
        timeout = 5 if self._client_status[stream_id] & LOCAL_CLOSED else 60
        sock = self._client_sock[stream_id]
        while True:
            ins, _, _ = select.select([sock], [], [], timeout)
            if not ins:
                sock.close()
                self._client_status[stream_id] = CLOSED
                self.send_frame(3, 0, stream_id, b'\x00' * random.randint(8, 256))
                self._stream_status[stream_id] = CLOSED
                return
            try:
                data = sock.recv(self.bufsize)
            except Exception:
                try:
                    sock.close()
                except OSError:
                    pass
                self._client_status[stream_id] = CLOSED
                self.send_frame(3, 0, stream_id, b'\x00' * random.randint(8, 256))
                self._stream_status[stream_id] = CLOSED
                return
            if not data:
                # close stream(LOCAL)
                self.send_frame(1, 1, stream_id, b'\x00' * random.randint(8, 256))
                self._stream_status[stream_id] |= LOCAL_CLOSED
                self._client_status[stream_id] |= REMOTE_CLOSED
                return
            if self._stream_status[stream_id] & LOCAL_CLOSED:
                sock.close()
                self._client_status[stream_id] = CLOSED
                self.send_frame(3, 0, stream_id, b'\x00' * random.randint(8, 256))
                self._stream_status[stream_id] = CLOSED
                return
            payload = struct.pack('>H', len(data)) + data + b'\x00' * random.randint(8, 256)
            self.send_frame(0, 0, stream_id, payload)

    def send_frame(self, type_, flags, stream_id, payload):
        logger.debug('send_frame type: %d, stream_id: %d' % (type_, stream_id))
        if self._sock is None:
            logger.error('connection closed. ' + self.name)
            return
        with self._connection_write_lock:
            header = struct.pack('>BBH', type_, flags, stream_id)
            data = header + payload
            ct = self.__cipher.encrypt(data)
            self._sock.sendall(struct.pack('>H', len(ct)) + ct)

    def send_ping(self):
        if self._last_ping == 0:
            self._last_ping = time.time()
            self.send_frame(6, 0, 0, b'\x00' * random.randint(64, 256))

    def read_from_connection(self):
        logger.debug('start read from connection')
        while True:
            # read frame_len
            timeout = 2 if self._last_ping else 10
            ins, _, _ = select.select([self._sock], [], [], timeout)
            if not ins:
                if self._last_ping:
                    logger.info('server no response ' + self.hxsServer.name)
                    break
                self.send_ping()
                continue

            try:
                frame_len = self._rfile.read(2)
                frame_len, = struct.unpack('>H', frame_len)
            except Exception as e:
                # destroy connection
                logger.error('read from connection error: %r' % e)
                break

            # read frame_data
            try:
                frame_data = self._rfile.read(frame_len)
                frame_data = self.__cipher.decrypt(frame_data)
            except (OSError, IOError, InvalidTag) as e:
                # destroy connection
                logger.error('read frame data error: %r' % e)
                break

            # parse chunk_data
            # +------+-------------------+----------+
            # | type | flags | stream_id | payload  |
            # +------+-------------------+----------+
            # |  1   |   1   |     2     | Variable |
            # +------+-------------------+----------+

            header, payload = frame_data[:4], frame_data[4:]
            frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
            payload = io.BytesIO(payload)
            logger.debug('recv frame_type: %s, stream_id: %s' % (frame_type, stream_id))

            if frame_type == 0:
                # DATA
                # first 2 bytes of payload indicates data_len, the rest would be padding
                data_len, = struct.unpack('>H', payload.read(2))
                data = payload.read(data_len)
                if len(data) != data_len:
                    # something went wrong, destory connection
                    break
                # check if stream writable
                if self._client_status[stream_id] & LOCAL_CLOSED:
                    continue
                # sent data to stream
                try:
                    self._client_sock[stream_id].sendall(data)
                except (OSError, IOError) as e:
                    # TODO: remote closed, reset stream
                    try:
                        self._client_sock[stream_id].close()
                    except (OSError, IOError):
                        pass
                    self._client_status[stream_id] = CLOSED
                    self.send_frame(3, 0, stream_id, b'\x00' * random.randint(8, 256))
                    self._stream_status[stream_id] = CLOSED
            elif frame_type == 1:
                # HEADER
                if self._next_stream_id == stream_id:
                    # server is not supposed to open a new stream
                    # send connection error?
                    break
                elif stream_id < self._next_stream_id:
                    if frame_flags == END_STREAM_FLAG:
                        if self._stream_status[stream_id] == OPEN:
                            self._stream_status[stream_id] = REMOTE_CLOSED
                            try:
                                self._client_sock[stream_id].shutdown(socket.SHUT_WR)  # KeyError?
                            except KeyError:
                                pass
                            self._client_status[stream_id] = LOCAL_CLOSED
                        elif self._stream_status[stream_id] == LOCAL_CLOSED:
                            self._stream_status[stream_id] = CLOSED
                            self._client_sock[stream_id].close()
                            self._client_sock[stream_id] = CLOSED
                            del self._client_sock[stream_id]
                        else:
                            # something wrong
                            pass
                    else:
                        # confirm a stream is opened
                        if isinstance(self._client_status[stream_id], Event):
                            self._stream_status[stream_id] = OPEN
                            self._client_status[stream_id].set()
                        else:
                            # close stream
                            self._stream_status[stream_id] = CLOSED
                            self.send_frame(3, 0, stream_id, b'\x00' * random.randint(8, 256))
            elif frame_type == 3:
                # RST_STREAM
                self._stream_status[stream_id] = CLOSED
                if stream_id in self._client_sock:
                    self._client_status[stream_id] = CLOSED
                    self._client_sock[stream_id].close()
                    del self._client_sock[stream_id]

            elif frame_type == 6:
                # PING
                if frame_flags == 1:
                    resp_time = time.time() - self._last_ping
                    logger.info('server response time: %.3f %s' % (resp_time, self.hxsServer.name))
                    self._last_ping = 0
                else:
                    self.send_frame(6, 1, 0, b'\x00' * random.randint(64, 256))
            elif frame_type == 7:
                # GOAWAY
                # no more new stream
                max_stream_id = payload.read(2)
                self._manager.remove(self)
                for stream_id, sock in self._client_sock:
                    if stream_id > max_stream_id:
                        # reset stream
                        pass
            elif frame_type == 8:
                # WINDOW_UPDATE
                pass
            else:
                break
        # out of loop, destroy connection
        logger.info('out of loop ' + self.hxsServer.name)
        self._manager.remove(self)
        self._rfile.close()

        for sid, status in self._client_status.items():
            if isinstance(status, Event):
                self._stream_status[sid] = CLOSED
                status.set()

        try:
            if self._sock:
                self._sock.close()
                self._sock = None
        except (OSError, IOError):
            pass
        for stream_id, sock in self._client_sock.items():
            try:
                sock.close()
            except:
                pass

    def getKey(self):
        logger.debug('hxsocks2 getKey')
        host, port, usn, psw = (self.hxsServer.hostname, self.hxsServer.port, self.hxsServer.username, self.hxsServer.password)
        logger.debug('hxsocks2 connect to server')
        from connection import create_connection
        self._sock = create_connection((host, port), self.timeout, parentproxy=self.parentproxy, tunnel=True)

        self._rfile = self._sock.makefile('rb')

        acipher = ECC(self.__pskcipher._key_len)
        pubk = acipher.get_pub_key()
        logger.debug('hxsocks2 send key exchange request')
        ts = int(time.time()) // 30
        ts = struct.pack('>I', ts)
        padding_len = random.randint(64, 255)
        data = b''.join([chr(len(pubk)).encode('latin1'),
                         pubk,
                         hmac.new(psw.encode(), ts + pubk + usn.encode(), hashlib.sha256).digest(),
                         b'\x00' * padding_len])
        data = chr(20).encode() + struct.pack('>H', len(data)) + data

        ct = self.__pskcipher.encrypt(data)
        self._sock.sendall(ct)

        self.__pskcipher.decrypt(self._rfile.read(self.__pskcipher._iv_len))

        if encrypt.is_aead(self.method):
            ct_len = self.__pskcipher.decrypt(self._rfile.read(18))
            ct_len, = struct.unpack('!H', ct_len)
            ct = self.__pskcipher.decrypt(self._rfile.read(ct_len + 16))
            data = ct[2:]
        else:
            resp_len = self.__pskcipher.decrypt(self._rfile.read(2))
            resp_len, = struct.unpack('>H', resp_len)
            data = self.__pskcipher.decrypt(self._rfile.read(resp_len))

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
            server_id = '%s_%d' % (host, port)
            if server_id not in known_hosts:
                logger.info('hxs: server %s new cert %s saved.' % (server_id, hashlib.sha256(server_cert).hexdigest()[:8]))
                with open('./.hxs_known_hosts/' + server_id + '.cert', 'wb') as f:
                    f.write(server_cert)
                    known_hosts[server_id] = server_cert
            elif known_hosts[server_id] != server_cert:
                logger.error('hxs: server %s certificate mismatch! PLEASE CHECK!' % server_id)
                raise OSError(0, 'hxs: bad certificate')

            if auth == hmac.new(psw.encode(), pubk + server_key + usn.encode(), hashlib.sha256).digest():
                try:
                    ECC.verify_with_pub_key(server_cert, auth, signature, self.hash_algo)
                    shared_secret = acipher.get_dh_key(server_key)
                    logger.debug('hxs key exchange success')
                    self.__cipher = AEncryptor(shared_secret, self.method, CTX)
                    return
                except InvalidSignature:
                    logger.error('hxs getKey Error: server auth failed, bad signature')
            else:
                logger.error('hxs getKey Error: server auth failed, bad username or password')
        else:
            logger.error('hxs getKey Error. bad password or timestamp.')
        raise OSError(0, 'hxs getKey Error')


if __name__ == '__main__':
    conn = hxs2_connection('hxs2://user:pass@127.0.0.1:8138/?PSK=password&method=aes-128-cfb')
    hxs = conn.connect(('www.baidu.com', 80))
    hxs.sendall(b'GET / HTTP/1.0\r\n\r\n')
    data = hxs.recv(1024)
    while data:
        print(repr(data))
        data = hxs.recv(1024)
