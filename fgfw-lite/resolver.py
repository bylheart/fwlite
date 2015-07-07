#!/usr/bin/env python
# coding: UTF-8
import os
import sys
import socket
import base64
import logging
import dnslib
import struct
import select
import traceback
from collections import defaultdict
from threading import RLock
from repoze.lru import lru_cache
from connection import create_connection
from apfilter import ap_filter
logger = logging.getLogger('FW_Lite')
try:
    from ipaddress import ip_address as _ip_address
except ImportError:
    from ipaddr import IPAddress as _ip_address

apfilter = ap_filter()
try:
    for path in ('./fgfw-lite/gfwlist.txt', 'gfwlist.txt'):
        if os.path.isfile(path):
            f = open(path)
            break
    else:
        raise
    data = f.read()
    if '!' not in data:
        data = ''.join(data.split())
        data = base64.b64decode(data).decode()
    for line in data.splitlines():
        if '||' in line:
            apfilter.add(line)
except:
    sys.stderr.write('resolver.py: gfwlist not found!\n')
    pass

proxy = '127.0.0.1:8118'

host_lock_map = defaultdict(RLock)


@lru_cache(4096, timeout=3600)
def ip_address(q):
    return _ip_address(q)


@lru_cache(4096, timeout=900)
def _resolver(host):
    return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]


def resolver(host):
    """return (family, ipaddr)
       >>>
       [(2, '82.94.164.162'),
        (10, '2001:888:2000:d::a2')]"""
    with host_lock_map[host]:
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except:
            pass
        try:
            if not is_poisoned(host):
                iplist = _resolver(host)
                if iplist:
                    return iplist
        except Exception as e:
            logger.debug('resolving %s: %r' % (host, e))
        try:
            record = get_record(host, 'ANY', ('114.114.114.114', 53), ('8.8.8.8', 53), proxy, recursive=True)
            return [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        except Exception as e:
            logger.debug('resolving %s: %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            return []


@lru_cache(1048, timeout=30)
def _udp_dns_records(host, qtype, server):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query_data, server)
    record_list = []
    while 1:
        try:
            (ins, _, _) = select.select([sock], [], [], 1)
            if not ins:
                break
            reply_data, reply_address = sock.recvfrom(8192)
            record_list.append(dnslib.DNSRecord.parse(reply_data))
        except:
            break
    return record_list


@lru_cache(1, timeout=30)
def is_udp_usable():
    query = dnslib.DNSRecord.question('twitter.com', qtype='A')
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query_data, ('8.8.8.8', 53))
    record_list = []
    while 1:
        try:
            (ins, _, _) = select.select([sock], [], [], 1)
            if not ins:
                break
            reply_data, reply_address = sock.recvfrom(8192)
            record_list.append(dnslib.DNSRecord.parse(reply_data))
        except:
            break
    return len(record_list) > 1


def udp_dns_records(host, qtype, server):
    result = _udp_dns_records(host, qtype, server) if is_udp_usable() else None
    if result:
        return result
    raise IOError(0, 'UDP resolve failed!')


@lru_cache(4096, timeout=900)
def _udp_dns_record(host, qtype, server):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    sock.sendto(query_data, server)
    reply_data, reply_address = sock.recvfrom(8192)
    record = dnslib.DNSRecord.parse(reply_data)
    return record


@lru_cache(4096, timeout=900)
def udp_dns_record(host, qtype, server):
    return udp_dns_records(host, qtype, server)[-1]


@lru_cache(4096, timeout=900)
def tcp_dns_record(host, proxy, qtype, server):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    for _ in range(2):
        try:
            sock = create_connection(server, ctimeout=5, parentproxy=proxy, tunnel=True)
            sock.send(struct.pack('>h', len(query_data)) + query_data)
            rfile = sock.makefile('rb')
            reply_data_length = rfile.read(2)
            reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
            record = dnslib.DNSRecord.parse(reply_data)
            sock.close()
            return record
        except Exception as e:
            logger.warning('tcp_dns_record %s failed. %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
    raise IOError(0, 'tcp_dns_record %s failed.' % host)


def get_record(host, qtype, localserver, remoteserver, proxy, recursive=False):
    '''used by resolver and dnsserver'''
    if not is_poisoned(host):
        return _udp_dns_record(host, qtype, localserver)
    # try:
    #     record = udp_dns_record(host, qtype, remoteserver)
    #     if record.header.tc == 1:
    #         raise ValueError('tc == 1')
    # except Exception as e:
    #     logger.debug('resolve %s via UDP failed! %r Try with TCP...' % (host, e))
    #     record = tcp_dns_record(host, proxy, qtype, remoteserver)
    record = tcp_dns_record(host, proxy, qtype, remoteserver)
    while recursive and len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
        # logger.debug('resolve %s CNAME: %s' % (host, record.rr[0].rdata))
        # try:
        #     record = udp_dns_record(str(record.rr[0].rdata), qtype, remoteserver)
        #     if record.header.tc == 1:
        #         raise ValueError('tc == 1')
        # except:
        #     logger.debug('resolve %s via UDP failed! %r Try with TCP...' % (host, e))
        #     record = tcp_dns_record(str(record.rr[0].rdata), proxy, qtype, remoteserver)
        record = tcp_dns_record(str(record.rr[0].rdata), proxy, qtype, remoteserver)
    return record

is_poisoned_cache = {}


def is_poisoned(host):
    if apfilter and apfilter.match(host, host, domain_only=True):
        return True
    # if host in is_poisoned_cache:
    #     return is_poisoned_cache[host]
    # try:
    #     result = udp_dns_records(host, 'A', ('8.8.8.8', 53))
    #     is_poisoned_cache[host] = len(result) > 1
    #     if len(result) > 1:
    #         logger.warning('%s is DNS poisoned!' % host)
    #     return len(result) > 1
    # except:
    #     pass


@lru_cache(1024, timeout=7200)
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
    print(resolver('www.youtube.com'))
    print(resolver('www.baidu.com'))
    print(is_poisoned('twitter.com'))
    print(is_udp_usable())
