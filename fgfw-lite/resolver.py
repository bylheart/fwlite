#!/usr/bin/env python
# coding: UTF-8
import socket
import logging
import dnslib
import struct
import select
import traceback
import time
import sys
from collections import defaultdict
from threading import RLock, Event, Thread
from repoze.lru import lru_cache
from connection import create_connection
logger = logging.getLogger('FW_Lite')
try:
    from ipaddress import ip_address as _ip_address
except ImportError:
    from ipaddr import IPAddress as _ip_address
apfilter = None
proxy = ''

host_lock_map = defaultdict(RLock)


@lru_cache(4096, timeout=3600)
def ip_address(q):
    return _ip_address(q)


@lru_cache(4096, timeout=900)
def _resolver(host):
    try:
        return [(i[0], i[4][0]) for i in socket.getaddrinfo(host, 0)]
    except Exception as e:
        raise e


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
            if apfilter and apfilter.match(host, host, domain_only=True):
                raise ValueError('in domain rules')
            iplist = _resolver(host)
            if not iplist:
                raise ValueError('empty iplist')
            return iplist
        except Exception as e:
            logger.debug('resolving %s: %r' % (host, e))
            try:
                record = tcp_dns_record(host, proxy)
                while len(record.rr) == 1 and record.rr[0].rtype == dnslib.QTYPE.CNAME:
                    logger.debug('resolve %s CNAME: %s' % (host, record.rr[0].rdata))
                    record = tcp_dns_record(str(record.rr[0].rdata), proxy)
                return [(2 if x.rtype == 1 else 10, str(x.rdata)) for x in record.rr if x.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA)]
            except:
                return []


def report_bad_host(host):
    '''this host could be dns poisoned, please check.'''
    pass


def udp_dns_records(host, qtype='A', dnsserver='8.8.8.8'):
    query = dnslib.DNSRecord.question(host, qtype=qtype)
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


class UDP_DNS_Resolver(object):
    def __init__(self, timeout=1):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.event_dict = defaultdict(MEvent)
        t = Thread(target=self.daemon)
        t.daemon = True
        t.start()

    def resolve(self, domain, qtype, server):
        request = dnslib.DNSRecord(q=dnslib.DNSQuestion(domain, qtype))
        request_id = request.header.id
        assert (server, request_id) not in self.event_dict
        data = request.pack()
        self.sock.sendto(data, server)
        try:
            result = self.event_dict[(server, request_id)].wait(self.timeout)
            assert isinstance(result, dnslib.DNSRecord)
        except Exception as e:
            del self.event_dict[(server, request_id)]
            raise e
        del self.event_dict[(server, request_id)]
        return result

    def daemon(self):
        while 1:
            try:
                (ins, _, _) = select.select([self.sock], [], [])
                reply_data, reply_address = self.sock.recvfrom(8192)
                record = dnslib.DNSRecord.parse(reply_data)
                if (reply_address, record.header.id) not in self.event_dict:
                    logger.warning('unexpected dns record:\n%s' % record)
                self.event_dict[(reply_address, record.header.id)].set(record)
            except:
                pass

udp_resolver = UDP_DNS_Resolver()


def _udp_dns_record(host, server=('8.8.8.8', 53), qtype='A'):
    return udp_resolver.resolve(host, getattr(dnslib.QTYPE, qtype), server)


@lru_cache(4096, timeout=900)
def is_poisoned(host):
    try:
        record = _udp_dns_record(host, qtype='AAAA')
        result = bool([r for r in record.rr if r.rtype is dnslib.QTYPE.A])
        return result
    except:
        return False


@lru_cache(4096, timeout=900)
def tcp_dns_record(host, proxy, server=('8.8.8.8', 53), qtype='ANY'):
    for _ in range(2):
        try:
            sock = create_connection(server, ctimeout=5, parentproxy=proxy, tunnel=True)
            query = dnslib.DNSRecord.question(host, qtype)
            query_data = query.pack()
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
    host = 'twitter.com'
    print(resolver(host))
    record_list = udp_dns_records(host, 'AAAA')
    for line in record_list:
        print(line)
        print()
    print(is_poisoned('twitter.com'))
