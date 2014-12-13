import socket
import ssl
import struct
from shadowsocks import sssocket
from parent_proxy import ParentProxy


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


def create_connection(netloc, timeout=None, source_address=None, iplist=None, parentproxy='', via=None):
    if not isinstance(parentproxy, ParentProxy):
        parentproxy = ParentProxy(parentproxy, parentproxy)
    if not parentproxy.proxy:
        return _create_connection(netloc, timeout or parentproxy.timeout, iplist=iplist)
    elif parentproxy.parse.scheme == 'http':
        return _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 80), timeout or parentproxy.timeout)
    elif parentproxy.parse.scheme == 'https':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 443), timeout or parentproxy.timeout)
        s = ssl.wrap_socket(s)
        s.do_handshake()
        return s
    elif parentproxy.parse.scheme == 'ss':
        s = sssocket(parentproxy.proxy, timeout, via.proxy, iplist=iplist)
        s.connect(netloc)
        return s
    elif parentproxy.parse.scheme == 'sni':
        return _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 443), timeout or parentproxy.timeout)
    elif parentproxy.parse.scheme == 'socks5':
        s = _create_connection((parentproxy.parse.hostname, parentproxy.parse.port or 1080), timeout or parentproxy.timeout)
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
        return s
    raise IOError(0, '_connect_via_proxy failed!')
