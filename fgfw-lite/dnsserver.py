#!/usr/bin/env python
# coding: UTF-8
#
# dnsserver.py   A anti-GFW DNS server
# by v3aqb

import random
import socket
import struct
import dnslib
from dnslib.server import BaseResolver
try:
    from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
except ImportError:
    from SocketServer import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
from resolver import get_record
import logging

logging.basicConfig(level=logging.INFO,
                    format='DNSServer %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')
logger = logging.getLogger('DNSServer')


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

        try:
            rdata = self.get_reply(data)

            if self.protocol == 'tcp':
                rdata = struct.pack("!H", len(rdata)) + rdata
                self.request.sendall(rdata)
            else:
                connection.sendto(rdata, self.client_address)

        except dnslib.DNSError as e:
            logger.error(repr(e))

    def get_reply(self, data):
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


class Resolver(BaseResolver):
    def __init__(self, localserver=('114.114.114.114', 53), remoteserver=('8.8.8.8', 53), proxy=None):
        self.localserver = localserver
        self.remoteserver = remoteserver
        self.proxy = proxy

    def resolve(self, request, handler):
        if len(request.questions) != 1:
            logging('more than one request question, abort.')
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'FORMERR')
            return reply

        try:
            return self.get_record(request)
        except Exception as e:
            logger.error('resolve %s failed. %s' % (request.header.qname, repr(e)))
            reply = request.reply()
            reply.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN')
            return reply

    def get_record(self, request):
        # return a record
        domain = str(request.questions[0].qname)[:-1]
        qtype = request.questions[0].qtype
        record = get_record(domain, qtype, self.localserver, self.remoteserver, self.proxy)
        reply = request.reply()
        reply.header.rcode = record.header.rcode
        reply.header.bitmap = record.header.bitmap
        for l in [record.rr, record.ar]:
            random.shuffle(l)
        reply.rr, reply.auth, reply.ar = record.rr, record.auth, record.ar
        return reply


def start_dns_server(server_address, localserver=('114.114.114.114', 53), remoteserver=('8.8.8.8', 53), proxy=None):
    resolver = Resolver(localserver, remoteserver, proxy)
    server = UDPDNSServer(server_address, DNSHandler, resolver)
    server.serve_forever()

if __name__ == '__main__':
    HOST, PORT = "localhost", 53
    print('starting server...')
    start_dns_server(('127.0.0.1', 53), proxy='http://127.0.0.1:8118')
