#!/usr/bin/env python
# coding: UTF-8
import sys
import dnslib
import struct
import socket
import select
import traceback
import logging
import time
from threading import Event, Thread
from collections import defaultdict

from repoze.lru import lru_cache
try:
    from ipaddress import ip_address as _ip_address
except:
    from ipaddr import IPAddress as _ip_address

from connection import create_connection


def ip_address(q):
    return _ip_address(q)


@lru_cache(1024, timeout=900)
def _resolver(host):
    return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]


@lru_cache(1024, timeout=900)
def _udp_dns_record(host, qtype, server):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(query_data, server)
    reply_data, reply_address = sock.recvfrom(8192)
    record = dnslib.DNSRecord.parse(reply_data)
    return record


@lru_cache(1024, timeout=900)
def _udp_dns_records(host, qtype, server):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query_data, server)
    record_list = []
    try:
        (ins, _, _) = select.select([sock], [], [], 1)
        if ins:
            reply_data, reply_address = sock.recvfrom(8192)
            record_list.append(dnslib.DNSRecord.parse(reply_data))
    finally:
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


@lru_cache(1024, timeout=900)
def tcp_dns_record(host, qtype, server, proxy):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    for _ in range(2):
        try:
            sock = create_connection(server, ctimeout=3, parentproxy=proxy, tunnel=True)
            sock.send(struct.pack('>h', len(query_data)) + query_data)
            rfile = sock.makefile('rb')
            reply_data_length = rfile.read(2)
            reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
            record = dnslib.DNSRecord.parse(reply_data)
            sock.close()
            return record
        except Exception as e:
            logging.warning('tcp_dns_record %s failed. %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
    raise IOError(0, 'tcp_dns_record %s failed.' % host)


class BaseResolver(object):
    def __init__(self, dnsserver):
        self.dnsserver = dnsserver

    def record(self, host, qtype):
        return _udp_dns_record(host, qtype, self.dnsserver)

    def resolve(self, host):
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except:
            pass
        try:
            record = self.record(host, 'ANY')
            while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
                record = self.record(str(record.rr[0].rdata), 'ANY')
            return [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        except Exception as e:
            logging.warning('resolving %s: %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            return []

    def get_ip_address(self, host):
        try:
            return ip_address(host)
        except:
            try:
                return ip_address(self.resolve(host)[0][1])
            except:
                return ip_address('8.8.8.8')


class MEvent(object):
    def __init__(self):
        self.__event = Event()
        self.msg = None
        self.time = time.time()

    def is_set(self):
        return self.__event.is_set()

    def set(self, msg):
        self.msg = msg
        self.__event.set()

    def clear(self, msg):
        self.__event.clear()
        self.msg = None

    def wait(self, timeout=None):
        self.__event.wait(timeout)
        msg, self.msg = self.msg, None
        return msg


class UDP_Resolver(BaseResolver):
    def __init__(self, dnsserver, timeout=3):
        self.dnsserver = dnsserver
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.event_dict = defaultdict(MEvent)
        t = Thread(target=self.daemon)
        t.daemon = True
        t.start()

    def record(self, domain, qtype):
        if isinstance(qtype, str):
            request = dnslib.DNSRecord.question(domain, qtype=qtype)
        else:
            request = dnslib.DNSRecord(q=dnslib.DNSQuestion(domain, qtype))
        while request.header.id in self.event_dict:
            if isinstance(qtype, str):
                request = dnslib.DNSRecord.question(domain, qtype=qtype)
            else:
                request = dnslib.DNSRecord(q=dnslib.DNSQuestion(domain, qtype))
        data = request.pack()
        self.sock.sendto(data, self.dnsserver)
        try:
            result = self.event_dict[request.header.id].wait(self.timeout)
            assert isinstance(result, dnslib.DNSRecord)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
        del self.event_dict[request.header.id]
        if result:
            return result
        raise IOError(0, 'udp_dns_record %s failed.' % domain)

    def daemon(self):
        while 1:
            try:
                (ins, _, _) = select.select([self.sock], [], [])
                reply_data, reply_address = self.sock.recvfrom(8192)
                record = dnslib.DNSRecord.parse(reply_data)
                if record.header.id in self.event_dict:
                    self.event_dict[record.header.id].set(record)
                else:
                    logging.warning('unexpected dns record:\n%s' % record)
            except:
                pass


class R_UDP_Resolver(BaseResolver):
    def __init__(self, dnsserver, timeout=1):
        # dnsserver should not be inside GFW
        self.dnsserver = dnsserver
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.event_dict = defaultdict(MEvent)
        t = Thread(target=self.daemon)
        t.daemon = True
        t.start()

    def record(self, domain, qtype):
        if isinstance(qtype, str):
            request = dnslib.DNSRecord.question(domain, qtype=qtype)
        else:
            request = dnslib.DNSRecord(q=dnslib.DNSQuestion(domain, qtype))
        while request.header.id in self.event_dict:
            if isinstance(qtype, str):
                request = dnslib.DNSRecord.question(domain, qtype=qtype)
            else:
                request = dnslib.DNSRecord(q=dnslib.DNSQuestion(domain, qtype))
        data = request.pack()
        self.sock.sendto(data, self.dnsserver)
        flag = 1
        result = None
        while 1:
            try:
                flag = self.event_dict[request.header.id].wait(self.timeout)
                assert isinstance(flag, dnslib.DNSRecord)
            except Exception as e:
                if not isinstance(e, AssertionError):
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                del self.event_dict[request.header.id]
                if not result:
                    raise IOError(0, 'reliable udp resolve failed! %s' % domain)
                return result
            else:
                result = flag

    def daemon(self):
        while 1:
            try:
                (ins, _, _) = select.select([self.sock], [], [])
                reply_data, reply_address = self.sock.recvfrom(8192)
                record = dnslib.DNSRecord.parse(reply_data)
                if (reply_address, record.header.id) in self.event_dict:
                    self.event_dict[(reply_address, record.header.id)].set(record)
                else:
                    logging.warning('unexpected dns record:\n%s' % record)
            except:
                pass


class TCP_Resolver(BaseResolver):
    def __init__(self, dnsserver, proxy=None):
        self.dnsserver = dnsserver
        self.proxy = proxy

    def record(self, domain, qtype):
        return tcp_dns_record(domain, qtype, self.dnsserver, self.proxy)


class Resolver(BaseResolver):
    def __init__(self, dnsserver, proxy=None):
        self.dnsserver = dnsserver
        self.UDP_Resolver = BaseResolver(dnsserver)
        self.TCP_Resolver = TCP_Resolver(dnsserver, proxy)

    def record(self, domain, qtype):
        record = self.UDP_Resolver.record(domain, qtype)
        if not record or record.header.tc == 1:
            record = self.TCP_Resolver.record(domain, qtype)
        return record


class Anti_GFW_Resolver(BaseResolver):
    def __init__(self, localdns, remotedns, proxy, apfilter):
        self.local = UDP_Resolver(localdns)
        self.remote = TCP_Resolver(remotedns, proxy)
        self.apfilter = apfilter

    def record(self, domain, qtype):
        try:
            if not self.is_poisoned(domain):
                return self.local.record(domain, qtype)
        except:
            logging.info('resolve %s via udp failed!' % domain)
        return self.remote.record(domain, qtype)

    def is_poisoned(self, domain):
        if self.apfilter and self.apfilter.match(domain, domain, True):
            return True


def get_resolver(localdns, remotedns=None, proxy=None, apfilter=None):
    if not remotedns or localdns == remotedns:
        return Resolver(localdns)
    else:
        return Anti_GFW_Resolver(localdns, remotedns, proxy, apfilter)

if __name__ == '__main__':
    from apfilter import ap_filter
    import base64
    apfilter = ap_filter()
    with open('./gfwlist.txt', 'r') as f:
        data = f.read()
        if '!' not in data:
            data = ''.join(data.split())
            data = base64.b64decode(data).decode()
        for line in data.splitlines():
            if '||' in line:
                apfilter.add(line)
    print(apfilter.match('twitter.com', 'twitter.com', True))
    resolver = get_resolver(('223.5.5.5', 53), ('8.8.8.8', 53), 'http://127.0.0.1:8119', apfilter)
    print(resolver.record('twitter.com', 'ANY'))
    print(resolver.resolve('twitter.com'))
    print(resolver.get_ip_address('twitter.com'))
