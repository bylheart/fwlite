import socket
import base64
import logging
import dnslib
import struct
from repoze.lru import lru_cache
from util import parse_hostport
from connection import create_connection
logger = logging.getLogger('FW_Lite')
try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address


@lru_cache(4096, timeout=90)
def resolver(host, backupserver='8.8.8.8'):
    """return (family, ipaddr)
       >>>
       [(2, '82.94.164.162'),
        (10, '2001:888:2000:d::a2')]"""
    try:
        return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]
    except Exception as e:
        logger.error(repr(e))
        return [(2, '0.0.0.0'), ]


@lru_cache(1024, timeout=90)
def get_ip_address(host):
    try:
        return ip_address(host)
    except Exception:
        return ip_address(resolver(host)[0][1])


def dns_via_tcp(query, httpproxy=None, dnsserver='8.8.8.8:53', user=None, passwd=None):
    server, port = parse_hostport(dnsserver, default_port=53)
    if ':' in server:
        server = '[%s]' % server
    dnsserver = '%s:%d' % (server, port)
    if httpproxy:
        sock = create_connection(parse_hostport(httpproxy), timeout=3)
        s = [b'CONNECT %s HTTP/1.1\r\n' % dnsserver]
        if user:
            a = '%s:%s' % (user, passwd)
            s.append(('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode())).encode())
        s.append(b'\r\n')
        sock.sendall(''.join(s).encode())
        remoterfile = sock.makefile('rb', 0)
        data = remoterfile.readline()
        while not data in (b'\r\n', b'\n', b'\r'):
            data = remoterfile.readline()
            if not data:
                break
    else:
        sock = create_connection(parse_hostport(dnsserver), timeout=3)
    query = dnslib.DNSRecord.question(query, qtype='ANY')
    query_data = query.pack()
    sock.send(struct.pack('>h', len(query_data)) + query_data)
    rfile = sock.makefile('r', 1024)
    reply_data_length = rfile.read(2)
    reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
    record = dnslib.DNSRecord.parse(reply_data)
    iplist = [str(x.rdata) for x in record.rr if x.rtype in (1, 28, 255)]
    sock.close()
    return iplist

if __name__ == '__main__':
    print dns_via_tcp('twitter.com')
