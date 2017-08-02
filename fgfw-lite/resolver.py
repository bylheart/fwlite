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
from threading import Event, Thread
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
        t = Thread(target=self._sched_clean, args=(CLEAN_INTV, ))
        t.daemon = True
        t.start()

    def cache(self, host, qtype, result):
        logger.debug('dns cache add: {} {!r} {}'.format(host, qtype, result.__class__.__name__))
        if not result or isinstance(result, Exception):
            self._bad_cache[self._bad_cache_id][(host, qtype)] = result
        else:
            self._cache[self._cache_id][(host, qtype)] = result

    def query(self, host, qtype):
        for v in self._cache:
            if (host, qtype) in v:
                logger.debug('dns cache hit: good, {} {!r}'.format(host, qtype))
                return v[(host, qtype)]
        for v in self._bad_cache:
            if (host, qtype) in v:
                logger.debug('dns cache hit: bad, {} {!r}'.format(host, qtype))
                return v[(host, qtype)]
        logger.debug('dns cache miss... {} {!r}'.format(host, qtype))

    def clear(self):
        self._cache = [{} for _ in range(NUM_CACHE)]
        self._bad_cache = [{} for _ in range(NUM_BAD_CACHE)]

    def _sched_clean(self, intv):
        while 1:
            time.sleep(intv)
            self._cache_id = next(self._cache_iter)
            self._bad_cache_id = next(self._bad_cache_iter)
            self._cache[self._cache_id] = {}
            self._bad_cache[self._bad_cache_id] = {}


dns_cache = DNS_Cache()


def getaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0):
    logger.debug('entering getaddrinfo()')
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
    logger.debug('entering _resolver()')
    return [(i[0], i[4][0]) for i in getaddrinfo(host, 0)]


def _udp_dns_record(host, qtype, server, timeout=3):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(query_data, server)
    reply_data, reply_address = sock.recvfrom(8192)
    record = dnslib.DNSRecord.parse(reply_data)
    return record


def tcp_dns_record(host, qtype, server, proxy, timeout=3):
    if isinstance(qtype, str):
        query = dnslib.DNSRecord.question(host, qtype=qtype)
    else:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(host, qtype))
    query_data = query.pack()
    sock = create_connection(server, ctimeout=3, parentproxy=proxy, tunnel=True)
    data = struct.pack('>h', len(query_data)) + query_data
    sock.sendall(bytes(data))
    sock.settimeout(timeout)
    rfile = sock.makefile('rb')
    reply_data_length = rfile.read(2)
    reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
    record = dnslib.DNSRecord.parse(reply_data)
    sock.close()
    return record


class BaseResolver(object):
    def __init__(self, dnsserver):
        self.dnsserver = tuple(dnsserver)

    def record(self, host, qtype):
        logger.debug('entering %s.record()... %r' % (self.__class__.__name__, self))
        result = dns_cache.query(host, (qtype, self.dnsserver))
        if result:
            if isinstance(result, Exception):
                raise result
            if result.header.rcode in (dnslib.RCODE.REFUSED, ):
                raise ValueError('server refused.')
            return result
        try:
            result = self._record(host, qtype)
            # check result
            dns_cache.cache(host, (qtype, self.dnsserver), result)
            logger.debug('dns success...')
        except Exception as e:
            logger.debug('dns error: %r' % e)
            dns_cache.cache(host, (host, (qtype, self.dnsserver)), e)
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            raise e
        if result.header.rcode in (dnslib.RCODE.REFUSED, ):
            raise ValueError('server refused.')
        return result

    def resolve(self, host, dirty=False):
        logger.debug('entering %s.resolve()... %r' % (self.__class__.__name__, self))
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except Exception:
            pass
        try:
            record = self.record(host, 'ANY')
            while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
                record = self.record(str(record.rr[0].rdata), 'ANY')
            return [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
        except Exception as e:
            logger.warning('resolving %s failed: %r' % (host, e))
            traceback.print_exc(file=sys.stderr)
            return []

    def get_ip_address(self, host):
        logger.debug('entering %s.get_ip_address()... %r' % (self.__class__.__name__, self))
        try:
            return ip_address(host)
        except Exception:
            try:
                return ip_address(self.resolve(host, dirty=True)[0][1])
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
    def __init__(self, dnsserver, proxy=None, timeout=3):
        self.dnsserver = tuple(dnsserver)
        self.proxy = proxy
        self.timeout = timeout

    def _record(self, domain, qtype):
        return tcp_dns_record(domain, qtype, self.dnsserver[0], self.proxy, timeout=self.timeout)


class Resolver(BaseResolver):
    def __init__(self, dnsserver, timeout=3):
        self.dnsserver = tuple(dnsserver)
        self.UDP_Resolver = UDP_Resolver(dnsserver, timeout)
        self.TCP_Resolver = TCP_Resolver(dnsserver, timeout)

    def record(self, domain, qtype):
        record = self.UDP_Resolver.record(domain, qtype)
        if record and record.header.tc == 1:
            record = self.TCP_Resolver.record(domain, qtype)
        return record


class Anti_GFW_Resolver(BaseResolver):
    def __init__(self, localdns, remotedns, proxy, apfilter_list, bad_ip):
        logger.debug('localdns: %r' % localdns)
        logger.debug('remotedns: %r' % remotedns)
        self.local = Resolver(localdns)
        self.remote = TCP_Resolver(remotedns, proxy)
        self.apfilter_list = apfilter_list
        self.bad_ip = bad_ip

    def record(self, domain, qtype):
        try:
            if not self.is_poisoned(domain):
                record = self.local.record(domain, qtype)
                if any([str(x.rdata) in self.bad_ip for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]):
                    raise ValueError('ip in bad_ip list')
                return record
        except Exception as e:
            logger.info('resolve %s via local failed! %r' % (domain, e))
        return self.remote.record(domain, qtype)

    def is_poisoned(self, domain):
        if not self.apfilter_list:
            return
        for apfilter in self.apfilter_list:
            if apfilter and apfilter.match(domain, domain, True):
                return True

    def resolve(self, host, dirty=False):
        try:
            ip = ip_address(host)
            return [(2 if ip._version == 4 else 10, host), ]
        except Exception:
            pass
        if not self.is_poisoned(host):
            try:
                result = self.local.resolve(host, dirty)
                if result:
                    return result
            except Exception as e:
                logger.info('resolve %s via local failed! %r' % (host, e))
        if dirty:
            return []
        return self.remote.resolve(host)


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
    print('test apfilter...')
    print(apfilter.match('twitter.com', 'twitter.com', True))
    print(apfilter.match('www.163.com', 'www.163.com', True))

    resolver = get_resolver([('119.29.29.29', 53), ], [('8.8.8.8', 53), ], 'http://127.0.0.1:8119', [apfilter, ])
    # print(resolver.record('twitter.com', 'ANY'))
    print(resolver.resolve('twitter.com'))
    print(resolver.get_ip_address('twitter.com'))
    print(resolver.get_ip_address('www.163.com'))
