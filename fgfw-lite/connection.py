#!/usr/bin/env python
# coding: UTF-8
import socket
import base64
import struct
import logging
import random

from parent_proxy import ParentProxy
from httputil import read_response_line, read_header_data

logger = logging.getLogger('conn')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


def _create_connection(address, timeout=None, source_address=None, iplist=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.
    """
    host, port = address
    try:
        import config
        resolver = config.conf.resolver.resolve
    except Exception:
        def resolver(host):
            return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]
    err = None
    if not iplist:
        iplist = resolver(host)

    if not iplist:
        raise socket.error("getaddrinfo returns an empty list")

    if len(iplist) > 1:
        random.shuffle(iplist)
        # ipv4 goes first
        iplist = sorted(iplist, key=lambda item: item[0])

    for res in iplist:
        af, addr = res
        sock = None
        try:
            sock = socket.socket(af)
            if timeout:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect((addr, port))
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()
    raise err


def do_tunnel(soc, netloc, pp):
    s = ['CONNECT %s:%s HTTP/1.1\r\n' % (netloc[0], netloc[1]), ]
    if pp.username:
        a = '%s:%s' % (pp.username, pp.password)
        s.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode()))
    s.append('Host: %s:%s\r\n\r\n' % (netloc[0], netloc[1]))
    soc.sendall(''.join(s).encode())
    remoterfile = soc.makefile('rb', 0)
    line, version, status, reason = read_response_line(remoterfile)
    if status != 200:
        raise IOError(0, 'create tunnel via %s failed!' % pp.name)
    read_header_data(remoterfile)


def create_connection(netloc, ctimeout=None, source_address=None, iplist=None, parentproxy=None, tunnel=False):
    if parentproxy and not isinstance(parentproxy, ParentProxy):
        logger.warning('parentproxy is not a ParentProxy instance, please check. %s' % (parentproxy))
        parentproxy = ParentProxy(parentproxy, parentproxy)
    ctimeout = ctimeout or parentproxy.timeout
    via = parentproxy.get_via() if parentproxy else None
    s = None
    if not parentproxy or not parentproxy.proxy:
        return _create_connection(netloc, ctimeout, iplist=iplist)
    elif parentproxy.scheme == 'http':
        s = create_connection((parentproxy.hostname, parentproxy.port or 80), ctimeout, source_address, parentproxy=via, tunnel=True)
        if tunnel:
            do_tunnel(s, netloc, parentproxy)
    elif parentproxy.scheme == 'ss':
        from sssocket import sssocket
        s = sssocket(parentproxy, ctimeout, via)
        s.connect(netloc)
    elif parentproxy.scheme == 'hxs':
        from hxsocks import hxssocket
        s = hxssocket(parentproxy, ctimeout, via)
        s.connect(netloc)
    elif parentproxy.scheme == 'hxs2':
        from hxsocks2 import hxs2_get_connection
        conn = hxs2_get_connection(parentproxy, ctimeout, via)
        s = conn.connect(netloc, ctimeout)
    elif parentproxy.scheme == 'socks5':
        s = create_connection((parentproxy.hostname, parentproxy.port or 1080), ctimeout, source_address, parentproxy=via, tunnel=True)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"\x05\x02\x00\x02" if parentproxy.username else b"\x05\x01\x00")
        data = s.recv(2)
        if data == b'\x05\x02':  # basic auth
            s.sendall(b''.join([b"\x01",
                                chr(len(parentproxy.username)).encode(),
                                parentproxy.username.encode(),
                                chr(len(parentproxy.password)).encode(),
                                parentproxy.password.encode()]))
            data = s.recv(2)
        assert data[1] == b'\x00'  # no auth needed or auth passed
        s.sendall(b''.join([b"\x05\x01\x00\x03",
                            chr(len(netloc[0])).encode(),
                            netloc[0].encode(),
                            struct.pack(b">H", netloc[1])]))
        data = s.recv(4)
        assert data[1] == b'\x00'
        if data[3] == b'\x01':  # read ipv4 addr
            s.recv(4)
        elif data[3] == b'\x03':  # read host addr
            s.recv(ord(s.recv(1)))
        elif data[3] == b'\x04':  # read ipv6 addr
            s.recv(16)
        s.recv(2)  # read port
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    else:
        raise IOError(0, 'parentproxy %s not supported!' % parentproxy.name)
    if s:
        return s
    raise IOError(0, 'create_connection failed!')
