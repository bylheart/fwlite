#!/usr/bin/env python
# coding: UTF-8
import socket
import logging
import dnslib
import struct
from repoze.lru import lru_cache
from connection import create_connection
logger = logging.getLogger('FW_Lite')
try:
    from ipaddress import ip_address as _ip_address
except ImportError:
    from ipaddr import IPAddress as _ip_address

badip = set()


@lru_cache(4096, timeout=3600)
def ip_address(q):
    return _ip_address(q)


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
        ip = ip_address(host)
        return [(2 if ip._version == 4 else 10, host), ]
    except:
        pass
    try:
        iplist = _resolver(host)
        verify_iplist(iplist)
        return iplist
    except Exception as e:
        logger.debug('resolving %s: %r' % (host, e))
        fake_iplist = iplist
        logger.debug('fake ip list: %s' % (fake_iplist))
        record = tcp_dns_record(host)
        while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
            logger.debug('resolve %s CNAME: %s' % (host, record.rr[0].rdata))
            record = tcp_dns_record(str(record.rr[0].rdata))
        iplist = [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        return iplist


def verify_iplist(iplist):
    if not iplist:
        raise ValueError('Empty iplist')
    if len(iplist) == 1:
        if iplist[0][1] in badip:
            raise ValueError('Bad ip')
        # raise ValueError('only 1 answer, could be bad ip')


def report_bad_host(host):
    '''this host could be dns poisoned, please check.'''
    pass


def udp_dns_records(host, dnsserver='8.8.8.8'):
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.sendto(query_data, (dnsserver, 53))
    tcp = 0
    record_list = []
    while 1:
        try:
            reply_data, reply_address = sock.recvfrom(8192)
            record = dnslib.DNSRecord.parse(reply_data)
            record_list.append(record)
            if record.header.tc == 1:
                tcp = 1
                break
        except:
            break
    if tcp:
        return []
    return record_list


@lru_cache(4096, timeout=90)
def tcp_dns_record(host):
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
            logger.warning('get_dns_record %s failed. %r' % (host, e))


@lru_cache(1024, timeout=90)
def get_ip_address(host):
    try:
        return ip_address(host)
    except:
        try:
            return ip_address(resolver(host)[0][1])
        except:
            return None


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    host = 'twitter.com'
    print(resolver(host))
    record_list = udp_dns_records(host)
    for line in record_list:
        print(line)
        print()
