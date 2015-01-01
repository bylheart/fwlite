import socket
import ssl
import base64
import struct
import logging
from shadowsocks import sssocket
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
        iplist = resolver.resolver(host)
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


def do_tunnel(soc, netloc, pp, timeout):
        s = ['CONNECT %s:%s HTTP/1.1\r\n' % (netloc[0], netloc[1]), ]
        if pp.parse.username:
            a = '%s:%s' % (pp.parse.username, pp.parse.password)
            s.append('Proxy-Authorization: Basic %s' % base64.b64encode(a.encode()))
        s.append('\r\n\r\n')
        soc.settimeout(timeout)
        soc.sendall(''.join(s).encode())
        remoterfile = soc.makefile('rb', 0)
        line, version, status, reason = read_reaponse_line(remoterfile)
        if status != 200:
            raise IOError(0, 'remote closed')
        read_header_data(remoterfile)


def create_connection(netloc, ctimeout=None, rtimeout=None, source_address=None, iplist=None, parentproxy=None, via=None, tunnel=False):
    logger.debug('connection.create_connection: %r %r %r %r' % (netloc, parentproxy, via, tunnel))
    if not isinstance(parentproxy, ParentProxy):
        parentproxy = parentproxy or ''
        parentproxy = ParentProxy(parentproxy, parentproxy)
    if via and not isinstance(via, ParentProxy):
        via = ParentProxy(via, via)
    ctimeout = ctimeout or 1
    rtimeout = rtimeout or parentproxy.timeout
    s = None
    if not parentproxy.proxy:
        s = _create_connection(netloc, ctimeout, iplist=iplist)
    elif parentproxy.parse.scheme == 'http':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 80), ctimeout)
        if tunnel:
            do_tunnel(s, netloc, parentproxy, rtimeout)
    elif parentproxy.parse.scheme == 'https':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 443), ctimeout)
        s = ssl.wrap_socket(s)
        s.do_handshake()
        if tunnel:
            do_tunnel(s, netloc, parentproxy, rtimeout)
    elif parentproxy.parse.scheme == 'ss':
        s = sssocket(parentproxy, ctimeout, via, iplist=iplist)
        s.connect(netloc)
    elif parentproxy.parse.scheme == 'sni':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 443), ctimeout)
    elif parentproxy.parse.scheme == 'socks5':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 1080), ctimeout)
        s.settimeout(rtimeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"\x05\x02\x00\x02" if parentproxy.parse.username else b"\x05\x01\x00")
        data = s.recv(2)
        if data == b'\x05\x02':  # basic auth
            s.sendall(b''.join([b"\x01",
                                chr(len(parentproxy.parse.username)).encode(),
                                parentproxy.parse.username.encode(),
                                chr(len(parentproxy.parse.password)).encode(),
                                parentproxy.parse.password.encode()]))
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
        s.settimeout(rtimeout)
        return s
    raise IOError(0, 'create_connection failed!')
