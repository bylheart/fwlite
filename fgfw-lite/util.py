#!/usr/bin/env python
#-*- coding: UTF-8 -*-
#
# FGFW_Lite.py A Proxy Server help go around the Great Firewall
#
# Copyright (C) 2012-2014 Jiang Chao <sgzz.cj@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses>.

import base64
import re
import errno
import thread
import socket
import select
import struct
import dnslib
import logging
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

logger = logging.getLogger('FW_Lite')


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    optionxform = str

    def dget(self, section, option, default=''):
        try:
            value = self.get(section, option)
            if not value:
                value = default
        except Exception:
            value = default
        return value

    def dgetfloat(self, section, option, default=0):
        try:
            return self.getfloat(section, option)
        except Exception:
            return float(default)

    def dgetint(self, section, option, default=0):
        try:
            return self.getint(section, option)
        except Exception:
            return int(default)

    def dgetbool(self, section, option, default=False):
        try:
            return self.getboolean(section, option)
        except Exception:
            return bool(default)

    def items(self, section):
        try:
            return configparser.ConfigParser.items(self, section)
        except Exception:
            return []

    def set(self, section, option, value):
        if not self.has_section(section):
            self.add_section(section)
        configparser.ConfigParser.set(self, section, option, value)


def forward_socket(local, remote, timeout, bufsize):
    """forward socket"""
    def __io_copy(dest, source, timeout):
        try:
            dest.settimeout(timeout)
            source.settimeout(timeout)
            while 1:
                data = source.recv(bufsize)
                if not data:
                    break
                dest.sendall(data)
        except socket.timeout:
            pass
        except (OSError, IOError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            for sock in (dest, source):
                try:
                    sock.close()
                except StandardError:
                    pass
    thread.start_new_thread(__io_copy, (remote.dup(), local.dup(), timeout))
    __io_copy(local, remote, timeout)


def dns_via_tcp(query, httpproxy=None, dnsserver='8.8.8.8:53', user=None, passwd=None):
    from connection import create_connection
    server, port = parse_hostport(dnsserver, default_port=53)
    if ':' in server:
        server = '[%s]' % server
    dnsserver = '%s:%d' % (server, port)
    if httpproxy:
        sock = create_connection(parse_hostport(httpproxy), ctimeout=3, rtimeout=3)
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
        sock = create_connection(parse_hostport(dnsserver), ctimeout=3, rtimeout=3)
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


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def is_connection_dropped(lst):  # modified from urllib3
    """
    Returns sockets if the connection is dropped and should be closed.

    """
    try:
        return select.select(lst, [], [], 0.0)[0]
    except socket.error:
        return lst


def sizeof_fmt(num):
    if num < 1024:
        return "%dB" % num
    for x in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return "%.1f%s" % (num, x)
        num /= 1024.0
    return "%.1f%s" % (num, 'TB')


if __name__ == "__main__":
    pass
