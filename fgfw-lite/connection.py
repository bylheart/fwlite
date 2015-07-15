#!/usr/bin/env python
# coding: UTF-8
import socket
import ssl
import base64
import struct
import logging
import random
from shadowsocks import sssocket
from hxsocks import hxssocket
from parent_proxy import ParentProxy
from httputil import read_reaponse_line, read_header_data
logger = logging.getLogger('FW_Lite')


def _create_connection(address, timeout=object(), source_address=None, iplist=None):
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
    import resolver
    host, port = address
    err = None
    if not iplist:
        iplist = resolver._resolver(host)
    if len(iplist) > 1:
        random.shuffle(iplist)
        # ipv4 goes first
        iplist = sorted(iplist, key=lambda item: item[0])
    for res in iplist:
        af, addr = res
        sock = None
        try:
            sock = socket.socket(af)
            if timeout is not object():
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect((addr, port))
            return sock

        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


def do_tunnel(soc, netloc, pp):
    s = ['CONNECT %s:%s HTTP/1.1\r\n' % (netloc[0], netloc[1]), ]
    if pp.username:
        a = '%s:%s' % (pp.username, pp.password)
        s.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode()))
    s.append('Host: %s:%s\r\n\r\n' % (netloc[0], netloc[1]))
    soc.sendall(''.join(s).encode())
    remoterfile = soc.makefile('rb', 0)
    line, version, status, reason = read_reaponse_line(remoterfile)
    if status != 200:
        raise IOError(0, 'create tunnel via %s failed!' % pp.name)
    read_header_data(remoterfile)


def create_connection(netloc, ctimeout=None, source_address=None, iplist=None, parentproxy='direct', via='', tunnel=False):
    logger.debug('connection.create_connection: %r %r %r %r' % (netloc, parentproxy, via, tunnel))
    if not isinstance(parentproxy, ParentProxy):
        parentproxy = ParentProxy(parentproxy, parentproxy)
    if via and not isinstance(via, ParentProxy):
        via = ParentProxy('Via', via)
    ctimeout = ctimeout or parentproxy.timeout
    s = None
    if not parentproxy or not parentproxy.proxy:
        s = _create_connection(netloc, ctimeout, iplist=iplist)
    elif parentproxy.scheme == 'http':
        s = _create_connection((parentproxy.hostname, parentproxy.port or 80), ctimeout)
        if tunnel:
            do_tunnel(s, netloc, parentproxy)
    elif parentproxy.scheme == 'https':
        s = _create_connection((parentproxy.hostname, parentproxy.port or 443), ctimeout)
        s = ssl.wrap_socket(s)
        s.do_handshake()
        if tunnel:
            do_tunnel(s, netloc, parentproxy)
    elif parentproxy.scheme == 'ss':
        s = sssocket(parentproxy, ctimeout, via, iplist=iplist)
        s.connect(netloc)
    elif parentproxy.scheme == 'hxs':
        s = hxssocket(parentproxy, ctimeout, via, iplist=iplist)
        s.connect(netloc)
    elif parentproxy.scheme == 'sni':
        s = _create_connection((parentproxy.hostname, parentproxy.port or 443), ctimeout)
    elif parentproxy.scheme == 'socks5':
        s = _create_connection((parentproxy.hostname, parentproxy.port or 1080), ctimeout)
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
