import socket
import logging
import dnslib
import struct
from repoze.lru import lru_cache
from connection import create_connection
logger = logging.getLogger('FW_Lite')
try:
    from ipaddress import ip_address
except ImportError:
    from ipaddr import IPAddress as ip_address


badip_list = [
    '59.24.3.173',
    '213.207.85.148',
    '118.219.253.245',
    '37.61.54.158',
    ]
badip = set(badip_list)


@lru_cache(4096, timeout=90)
def _resolver(host):
    try:
        return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]
    except Exception as e:
        logger.error(repr(e))
        return []


def resolver(host):
    """return (family, ipaddr)
       >>>
       [(2, '82.94.164.162'),
        (10, '2001:888:2000:d::a2')]"""
    try:
        iplist = _resolver(host)
        verify_iplist(iplist)
        return iplist
    except Exception as e:
        logger.debug('resolving %s: %r' % (host, e))
        fake_iplist = iplist
        print(fake_iplist)
        record = get_dns_record(host)
        while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
            # CNAME
            logger.debug('resolve %s CNAME: %s' % (host, record.rr[0].rdata))
            record = get_dns_record(str(record.rr[0].rdata))
        iplist = [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        return iplist


def verify_iplist(iplist):
    if not iplist:
        raise ValueError('Empty iplist')
    if len(iplist) == 1:
        if iplist[0][1] in badip:
            raise ValueError('Bad ip')


@lru_cache(4096, timeout=90)
def get_dns_record(host):
    for _ in range(2):
        try:
            sock = create_connection(('8.8.8.8', 53), ctimeout=1, rtimeout=5, parentproxy='127.0.0.1:8118', tunnel=True)
            query = dnslib.DNSRecord.question(host, qtype='ANY')
            query_data = query.pack()
            sock.send(struct.pack('>h', len(query_data)) + query_data)
            rfile = sock.makefile('rb')
            reply_data_length = rfile.read(2)
            reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
            record = dnslib.DNSRecord.parse(reply_data)
            sock.close()
            return record
        except Exception as e:
            logger.warning('resolve %s failed. %r' % (host, e))


@lru_cache(1024, timeout=90)
def get_ip_address(host):
    try:
        return ip_address(host)
    except Exception:
        return ip_address(resolver(host)[0][1])


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    print(resolver('twitter.com'))
