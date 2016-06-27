#!/usr/bin/env python
# coding: UTF-8
#
# dnsserver.py   A anti-GFW DNS server
# by v3aqb

import sys
import random
import socket
import struct
import dnslib
from dnslib.server import BaseResolver
try:
    from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
except ImportError:
    from SocketServer import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
import logging

logger = logging.getLogger('DNS_Server')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


class UDPDNSServer(ThreadingMixIn, UDPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler, resolver, bind_and_activate=True):
        self.resolver = resolver
        logger.info('starting UDP DNS server at %s:%s' % (server_address[0], server_address[1]))
        UDPServer.__init__(self, server_address, handler, bind_and_activate)


class TCPDNSServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler, resolver, bind_and_activate=True):
        self.resolver = resolver
        logger.info('starting TCP DNS server at %s:%s' % (server_address[0], server_address[1]))
        TCPServer.__init__(self, server_address, handler, bind_and_activate)


class DNSHandler(BaseRequestHandler):
    """
        Modified from dnslib.server.DNSHandler
    """

    udplen = 0                  # Max udp packet length (0 = ignore)

    def handle(self):
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            length = struct.unpack("!H", bytes(data[:2]))[0]
            while len(data) - 2 < length:
                data += self.request.recv(8192)
            data = data[2:]
        else:
            self.protocol = 'udp'
            data, connection = self.request

        rdata = self.get_reply(data)

        if self.protocol == 'tcp':
            rdata = struct.pack("!H", len(rdata)) + rdata
            self.request.sendall(rdata)
        else:
            connection.sendto(rdata, self.client_address)

    def get_reply(self, data):
        try:
            request = dnslib.DNSRecord.parse(data)

            resolver = self.server.resolver
            reply = resolver.resolve(request, self)

            if self.protocol == 'udp':
                rdata = reply.pack()
                if self.udplen and len(rdata) > self.udplen:
                    truncated_reply = reply.truncate()
                    rdata = truncated_reply.pack()
            else:
                rdata = reply.pack()

            return rdata
        except Exception as e:
            logger.error(repr(e))


class Resolver(BaseResolver):
    def __init__(self, resolver):
        # resolver: from resolver.py
        self.resolver = resolver

    def resolve(self, request, handler):
        if len(request.questions) != 1:
            logger('more than one request question, abort.')
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'FORMERR')
            return reply

        try:
            return self.get_record(request)
        except Exception as e:
            sys.stderr.write(repr(request) + '\n')
            logger.error('resolve %s failed. %s' % (request.header.qname, repr(e)))
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN')
            return reply

    def get_record(self, request):
        # return a record
        domain = str(request.questions[0].qname)[:-1]
        qtype = request.questions[0].qtype
        record = self.resolver.record(domain, qtype)
        reply = request.reply()
        reply.header.rcode = record.header.rcode
        reply.header.bitmap = record.header.bitmap
        for l in [record.rr, record.ar]:
            random.shuffle(l)
        reply.rr, reply.auth, reply.ar = record.rr, record.auth, record.ar
        return reply


def start_dns_server(server_address, localserver=('223.5.5.5', 53), remoteserver=('8.8.8.8', 53), proxy=None):
    from resolver import get_resolver
    from apfilter import ap_filter
    import base64
    af = ap_filter()
    with open('gfwlist.txt') as f:
        data = f.read()
        if '!' not in data:
            data = ''.join(data.split())
            data = base64.b64decode(data).decode()
        for line in data.splitlines():
            if '||' in line:
                try:
                    af.add(line)
                except:
                    pass
    r = get_resolver(localserver, remoteserver, proxy, af)
    resolver = Resolver(r)
    server = UDPDNSServer(server_address, DNSHandler, resolver)
    server.serve_forever()

if __name__ == '__main__':
    HOST, PORT = "localhost", 53
    print('starting server...')
    start_dns_server(('127.0.0.1', 53), proxy='http://127.0.0.1:8118')
