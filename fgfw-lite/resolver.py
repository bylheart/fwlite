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
import itertools
from threading import Event, Timer, RLock, Thread
from collections import defaultdict

try:
    from ipaddr import IPAddress as ip_address
except ImportError:
    from ipaddress import ip_address

from connection import create_connection


logger = logging.getLogger('resolver')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


NUM_CACHE = 12
NUM_BAD_CACHE = 2
CLEAN_INTV = 10


class DNS_Cache(object):
    def __init__(self):
        self._cache = [{} for _ in range(NUM_CACHE)]
        self._bad_cache = [{} for _ in range(NUM_BAD_CACHE)]
        self._cache_iter = itertools.cycle(range(NUM_CACHE))
        self._cache_id = next(self._cache_iter)
        self._bad_cache_iter = itertools.cycle(range(NUM_BAD_CACHE))
        self._bad_cache_id = next(self._bad_cache_iter)
        self._lock = RLock()
        Timer(CLEAN_INTV, self._sched_clean, ()).start()

    def cache(self, host, qtype, result):
        with self._lock:
            if not result or isinstance(result, Exception):
                self._bad_cache[self._bad_cache_id][(host, qtype)] = result
            else:
                self._cache[self._cache_id][(host, qtype)] = result

    def query(self, host, qtype):
        with self._lock:
            for v in self._bad_cache:
                if (host, qtype) in v:
                    logger.debug('dns cache hit: bad result, {} {}'.format(host, qtype))
                    return v[(host, qtype)]
            for v in self._cache:
                if (host, qtype) in v:
                    logger.debug('dns cache hit: good result, {} {}'.format(host, qtype))
                    return v[(host, qtype)]
            logger.debug('dns cache hit: good result, {} {}'.format(host, qtype))

    def clean(self):
        with self._lock:
            self._cache = [{} for _ in range(NUM_CACHE)]
            self._bad_cache = [{} for _ in range(NUM_BAD_CACHE)]

    def _sched_clean(self):
        with self._lock:
            self._cache_id = next(self._cache_iter)
            self._bad_cache_id = next(self._bad_cache_iter)
            self._cache[self._cache_id] = {}
            self._bad_cache[self._bad_cache_id] = {}
        Timer(CLEAN_INTV, self._sched_clean, ()).start()

dns_cache = DNS_Cache()


def getaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0):
    result = dns_cache.query(host, (port, family, socktype, proto, flags))
    if result:
        if isinstance(result, Exception):
            raise result
        return result
    try:
        result = socket.getaddrinfo(host, port, family, socktype, proto, flags)
        dns_cache.cache(host, (port, family, socktype, proto, flags), result)
        return result
    except Exception as e:
        dns_cache.cache(host, (port, family, socktype, proto, flags), e)
        raise e


def _resolver(host):
    return [(i[0], i[4][0]) for i in getaddrinfo(host, 0)]


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
        (ins, _, _) = select.select([sock], [], [], 2)
        if ins:
            reply_data, reply_address = sock.recvfrom(8192)
            record_list.append(dnslib.DNSRecord.parse(reply_data))
    finally:
        while 1:
            try:
                (ins, _, _) = select.select([sock], [], [], 2)
                if not ins:
                    break
                reply_data, reply_address = sock.recvfrom(8192)
                record_list.append(dnslib.DNSRecord.parse(reply_data))
            except Exception:
                break
    return record_list


def tcp_dns_record(host, qtype, server, proxy):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = create_connection(server, ctimeout=5, parentproxy=proxy, tunnel=True)
    data = struct.pack('>h', len(query_data)) + query_data
    sock.sendall(bytes(data))
    sock.settimeout(5)
    rfile = sock.makefile('rb')
    reply_data_length = rfile.read(2)
    reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
    record = dnslib.DNSRecord.parse(reply_data)
    sock.close()
    return record


class BaseResolver(object):
    def __init__(self, dnsserver):
        self.hostlock = defaultdict(RLock)
        self.dnsserver = tuple(dnsserver)

    def record(self, host, qtype):
        with self.hostlock[(host, qtype)]:
            result = dns_cache.query(host, (qtype, self.dnsserver))
            if result:
                if isinstance(result, Exception):
                    raise result
                return result
            try:
                result = self._record(host, qtype)
                dns_cache.cache(host, (host, (qtype, self.dnsserver)), result)
                return result
            except Exception as e:
                dns_cache.cache(host, (host, (qtype, self.dnsserver)), e)
                raise e

    def _record(self, host, qtype):
        return _udp_dns_record(host, qtype, self.dnsserver[0])

    def resolve(self, host):
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except Exception:
            pass
        return _resolver(host)

    def get_ip_address(self, host):
        try:
            return ip_address(unicode(host))
        except Exception:
            try:
                return ip_address(unicode(self.resolve(host)[0][1]))
            except Exception:
                return ip_address(u'0.0.0.0')


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
        self.dnsserver = tuple(dnsserver)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.event_dict = defaultdict(MEvent)
        self.hostlock = defaultdict(RLock)
        t = Thread(target=self.daemon)
        t.daemon = True
        t.start()

    def _record(self, domain, qtype):
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
        for dnsserver in self.dnsserver:
            self.sock.sendto(data, dnsserver)
        try:
            result = self.event_dict[request.header.id].wait(self.timeout)
            del self.event_dict[request.header.id]
            assert isinstance(result, dnslib.DNSRecord)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
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
                    logger.debug('unexpected dns record:\n%s' % record)
            except Exception:
                pass


class R_UDP_Resolver(BaseResolver):
    def __init__(self, dnsserver, timeout=1):
        # dnsserver should not be inside GFW
        self.dnsserver = tuple(dnsserver)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.event_dict = defaultdict(MEvent)
        self.hostlock = defaultdict(RLock)
        t = Thread(target=self.daemon)
        t.daemon = True
        t.start()

    def _record(self, domain, qtype):
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
                    logger.warning('unexpected dns record:\n%s' % record)
            except Exception:
                pass


class TCP_Resolver(BaseResolver):
    def __init__(self, dnsserver, proxy=None):
        self.dnsserver = tuple(dnsserver)
        self.proxy = proxy
        self.hostlock = defaultdict(RLock)

    def _record(self, domain, qtype):
        return tcp_dns_record(domain, qtype, self.dnsserver[0], self.proxy)


class Resolver(BaseResolver):
    def __init__(self, dnsserver, proxy=None):
        self.dnsserver = dnsserver
        self.UDP_Resolver = UDP_Resolver(dnsserver)
        self.TCP_Resolver = TCP_Resolver(dnsserver, proxy)
        self.hostlock = defaultdict(RLock)

    def _record(self, domain, qtype):
        record = self.UDP_Resolver.record(domain, qtype)
        if record and record.header.tc == 1:
            record = self.TCP_Resolver.record(domain, qtype)
        return record


class Anti_GFW_Resolver(BaseResolver):
    def __init__(self, localdns, remotedns, proxy, apfilter_list, bad_ip):
        self.local = UDP_Resolver(localdns)
        self.remote = TCP_Resolver(remotedns, proxy)
        self.apfilter_list = apfilter_list
        self.bad_ip = bad_ip
        self.hostlock = defaultdict(RLock)

    def _record(self, domain, qtype):
        try:
            if not self.is_poisoned(domain):
                record = self.local.record(domain, qtype)
                if any([str(x.rdata) in self.bad_ip for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]):
                    logger.warning('ip in bad_ip list, host: %s' % domain)
                else:
                    return record
        except Exception:
            logger.info('resolve %s via udp failed!' % domain)
        return self.remote.record(domain, qtype)

    def is_poisoned(self, domain):
        if not self.apfilter_list:
            return
        for apfilter in self.apfilter_list:
            if apfilter and apfilter.match(domain, domain, True):
                return True

    def resolve(self, host):
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except Exception:
            pass
        if not self.is_poisoned(host):
            return _resolver(host)
        try:
            record = self.remote.record(host, 'ANY')
            while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
                record = self.remote.record(str(record.rr[0].rdata), 'ANY')
            return [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        except Exception as e:
            logger.warning('resolving %s failed: %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            return []


def get_resolver(localdns, remotedns=None, proxy=None, apfilter=None, bad_ip=None):
    bad_ip = bad_ip or set()
    if not remotedns or localdns == remotedns:
        return Resolver(localdns)
    else:
        return Anti_GFW_Resolver(localdns, remotedns, proxy, apfilter, bad_ip)

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
    resolver = get_resolver(('223.5.5.5', 53), ('8.8.8.8', 53), 'http://127.0.0.1:8119', [apfilter, ])
    print(resolver.record('twitter.com', 'ANY'))
    print(resolver.resolve('twitter.com'))
    print(resolver.get_ip_address('twitter.com'))
