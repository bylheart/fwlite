#!/usr/bin/env python
# coding: UTF-8
#
# FGFW_Lite.py A Proxy Server help go around the Great Firewall
#
# Copyright (C) 2012-2015 Jiang Chao <sgzz.cj@gmail.com>
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

from __future__ import print_function, division

__version__ = '4.11.1'

import sys
import os
import glob

sys.dont_write_bytecode = True
WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
os.chdir(WORKINGDIR)
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))
sys.path += glob.glob('%s/Python27/*.egg' % WORKINGDIR)
gevent = None
try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True, Event=True)
except ImportError:
    sys.stderr.write('Warning: gevent not found! Using thread instead...\n')
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('Warning: Please update gevent to the latest 1.0 version!\n')
from collections import deque
import subprocess
import shlex
import time
import re
import io
import errno
import atexit
import base64
import json
import ftplib
import random
import select
import socket
import traceback
try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import BytesIO as StringIO
from threading import Thread, Timer
import logging
import logging.handlers
logging.basicConfig(level=logging.INFO,
                    format='FWLite %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')

import config
from util import parse_hostport, is_connection_dropped, sizeof_fmt
from connection import create_connection
from httputil import read_reaponse_line, read_headers, read_header_data, httpconn_pool
try:
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ipaddress import ip_address
except ImportError:
    import urllib2
    import urlparse
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from ipaddr import IPAddress as ip_address

try:
    from _manager import on_finish
except ImportError:
    def on_finish(hdlr):
        pass


if sys.platform.startswith('win'):
    PYTHON2 = '"./Python27/python27.exe"'
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break

NetWorkIOError = (IOError, OSError)
DEFAULT_TIMEOUT = 5
FAKEGIF = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;'


class ClientError(OSError):
    pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, level=1, conf=None):
        self.proxy_level = level
        self.conf = conf
        self.logger = self.conf.logger
        self.logger.info('starting server at %s:%s, level %d' % (server_address[0], server_address[1], level))
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    ssrealip = None
    ssclient = ''
    shortpath = ''
    ppname = ''
    retryable = True
    HTTPCONN_POOL = httpconn_pool()

    def __init__(self, request, client_address, server):
        self.conf = server.conf
        self.logger = server.logger
        self.traffic_count = [0, 0]  # [read from client, write to client]
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _quote_html(self, html):
        return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header('Connection', 'keep_alive')
        self.send_header("Content-Length", '0')
        self.end_headers()

    def log_message(self, format, *args):
        pass

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPRequestHandler.finish(self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def send_error(self, code, message=None):
        """Send and log an error reply. """
        try:
            short, long = self.responses[code]
        except KeyError:
            short, long = '???', '???'
        if message is None:
            message = short
        explain = long
        # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
        content = (self.error_message_format %
                   {'code': code, 'message': self._quote_html(message), 'explain': explain})
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Connection', 'keep_alive')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self._wfile_write(content)

    def write(self, code=200, msg=None, ctype=None):
        if msg is None:
            msg = b''
        self.send_response(code)
        if ctype:
            self.send_header('Content-type', ctype)
        self.send_header('Content-Length', str(len(msg)))
        self.send_header('Connection', 'keep_alive')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self._wfile_write(msg)

    def connection_recv(self, size):
        try:
            data = self.connection.recv(size)
            self.traffic_count[0] += len(data)
            return data
        except NetWorkIOError as e:
            raise ClientError(e.errno, e.strerror)

    def rfile_read(self, size=-1):
        try:
            data = self.rfile.read(size)
            self.traffic_count[0] += len(data)
            return data
        except NetWorkIOError as e:
            raise ClientError(e.errno, e.strerror)

    def rfile_readline(self, size=-1):
        try:
            data = self.rfile.readline(size)
            self.traffic_count[0] += len(data)
            return data
        except NetWorkIOError as e:
            raise ClientError(e.errno, e.strerror)

    def _wfile_write(self, data):
        self.retryable = False
        try:
            self.traffic_count[1] += len(data)
            return self.wfile.write(data)
        except NetWorkIOError as e:
            raise ClientError(e.errno, e.strerror)


class ProxyHandler(HTTPRequestHandler):
    server_version = "FW-Lite/" + __version__
    protocol_version = "HTTP/1.1"
    bufsize = 8192
    timeout = 60

    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self.traffic_count = [0, 0]  # [read from client, write to client]

    def handle_one_request(self):
        self._proxylist = None
        self.remotesoc = None
        self.retryable = True
        self.rbuffer = deque()  # client read buffer: store request body, ssl handshake package for retry. no pop method.
        self.wbuffer = deque()  # client write buffer: read only once, not used in connect method
        self.wbuffer_size = 0
        self.shortpath = None
        self.failed_parents = []
        self.phase = ''
        self.path = ''
        self.count = 0
        self.traffic_count = [0, 0]  # [read from client, write to client]
        self.logmethod = self.logger.info
        try:
            HTTPRequestHandler.handle_one_request(self)
        except NetWorkIOError as e:
            if e.errno in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                self.close_connection = 1
            else:
                raise
        finally:
            if self.path:
                self.logger.debug(self.shortpath or self.path + ' finished.')
                self.logger.debug('upload: %d, download %d' % tuple(self.traffic_count))
            if self.remotesoc:
                self.remotesoc.close()
            on_finish(self)

    def getparent(self):
        if self._proxylist is None:
            ip = self.conf.resolver.get_ip_address(self.requesthost[0])
            self._proxylist = self.conf.PARENT_PROXY.parentproxy(self.path, self.requesthost, self.command, ip, self.server.proxy_level)
            self.logger.debug(repr(self._proxylist))
        if not self._proxylist:
            self.ppname = ''
            return 1
        self.pproxy = self._proxylist.pop(0)
        self.ppname = self.pproxy.name

    def do_GET(self):
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            return self.do_FTP()
        if self.path == '/pac':
            _ip = ip_address(parse_hostport(self.headers.get('Host', ''))[0])
            if _ip.is_loopback or str(_ip) in self.conf.local_ip:
                return self.write(msg=self.conf.PAC, ctype='application/x-ns-proxy-autoconfig')
        # transparent proxy
        if self.path.startswith('/'):
            if 'Host' not in self.headers:
                return self.send_error(403)
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)

        if self.path.startswith('http://http://'):
            self.path = self.path[7:]

        parse = urlparse.urlparse(self.path)

        if 'Host' not in self.headers:
            self.headers['Host'] = parse.netloc

        self.requesthost = parse_hostport(self.headers['Host'], 80)
        self.shortpath = '%s://%s%s%s%s' % (parse.scheme, parse.netloc, parse.path.split(':')[0], '?' if parse.query else '', ':' if ':' in parse.path else '')

        # redirector
        noxff = False
        new_url = self.conf.PARENT_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s' % (new_url, self.command, self.shortpath or self.path))
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                return self.send_error(int(new_url))
            elif new_url.lower() == 'noxff':
                noxff = True
            elif new_url.lower() == 'reset':
                self.close_connection = 1
                return
            elif new_url.lower() == 'adblock':
                return self.write(msg=FAKEGIF, ctype='image/gif')
            elif all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                random.shuffle(self._proxylist)
            else:
                return self.redirect(new_url)

        ip = self.conf.resolver.get_ip_address(self.requesthost[0])

        if ip.is_loopback or self.ssclient:
            if ip_address(self.client_address[0]).is_loopback:
                if self.requesthost[1] in range(self.conf.listen[1], self.conf.listen[1] + self.conf.profiles):
                    return self.api(parse)
            else:
                return self.send_error(403, 'Go fuck yourself!')

        if str(ip) == self.connection.getsockname()[0]:
            if self.requesthost[1] in range(self.conf.listen[1], self.conf.listen[1] + len(self.conf.userconf.dget('fgfwproxy', 'profile', '134'))):
                if self.conf.userconf.dgetbool('fgfwproxy', 'remoteapi', False):
                    return self.api(parse)
                return self.send_error(403)

        if not self.ssclient and self.conf.xheaders:
            ipl = [client_ip.strip() for client_ip in self.headers.get('X-Forwarded-For', '').split(',') if client_ip.strip()]
            ipl.append(self.client_address[0])
            self.headers['X-Forwarded-For'] = ', '.join(ipl)

        if noxff:
            del self.headers['X-Forwarded-For']

        self._do_GET()

    def _do_GET(self, retry=False):
        try:
            if retry:
                if self.remotesoc:
                    try:
                        self.remotesoc.close()
                    except:
                        pass
                    self.remotesoc = None
                self.failed_parents.append(self.ppname)
                self.count += 1
                if self.count > 10:
                    self.logger.error('for some strange reason retry time exceeded 10, pls check!')
                    return
            if not self.retryable:
                self.close_connection = 1
                self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
                return
            if self.getparent():
                self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
                return self.send_error(504)

            self.upstream_name = self.ppname if self.pproxy.proxy.startswith('http') else self.requesthost
            iplist = None
            if self.pproxy.name == 'direct' and self.requesthost[0] in self.conf.HOSTS and not self.failed_parents:
                iplist = self.conf.HOSTS.get(self.requesthost[0])
                self._proxylist.insert(0, self.pproxy)
            self.set_timeout()
            self.phase = 'http_connect_via_proxy'
            self.remotesoc = self._http_connect_via_proxy(self.requesthost, iplist)
            self.wbuffer = deque()
            self.wbuffer_size = 0
            # send request header
            self.phase = 'sending request header'
            s = []
            if self.pproxy.proxy.startswith('http'):
                path = self.path
                if iplist:
                    path = self.path.split('/')
                    path[2] = '%s%s' % (iplist[0][1], ((':%d' % self.requesthost[1]) if self.requesthost[1] != 80 else ''))
                    path = ''.join(path)
                s.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
                if self.pproxy.username:
                    a = '%s:%s' % (self.pproxy.username, self.pproxy.password)
                    self.headers['Proxy-Authorization'] = 'Basic %s' % base64.b64encode(a.encode())
            else:
                s.append('%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version))
            # Does the client want to close connection after this request?
            conntype = self.headers.get('Connection', "")
            if self.request_version >= b"HTTP/1.1":
                client_close = 'close' in conntype.lower()
            else:
                client_close = 'keep_alive' in conntype.lower()
            if 'Upgrade' in self.headers:
                if 'websocket' in self.headers['Upgrade']:
                    self.headers['Upgrade'] = 'websocket'
                    client_close = True
                else:
                    self.logger.warning('Upgrade header found! (%s), FW-Lite do not support this...' % self.headers['Upgrade'])
                    del self.headers['Upgrade']
            else:
                self.headers['Connection'] = 'keep_alive'
            del self.headers['Proxy-Connection']
            for k, v in self.headers.items():
                if isinstance(v, bytes):
                    v = v.decode('latin1')
                s.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in k.split("-")]), v))
            s.append("\r\n")
            data = ''.join(s).encode('latin1')
            self.remotesoc.sendall(data)
            self.traffic_count[0] += len(data)
            # Now remotesoc is connected, set read timeout
            self.remotesoc.settimeout(self.rtimeout)
            remoterfile = self.remotesoc.makefile('rb', 0)
            # Expect
            skip = False
            if 'Expect' in self.headers:
                try:
                    response_line, protocol_version, response_status, response_reason = read_reaponse_line(remoterfile)
                except Exception as e:
                    # TODO: probably the server don't handle Expect well.
                    self.logger.warning('read response line error: %r' % e)
                else:
                    if response_status == 100:
                        hdata = read_header_data(remoterfile)
                        self._wfile_write(response_line + hdata)
                    else:
                        skip = True
            # send request body
            if not skip:
                self.phase = 'sending request body'
                content_length = int(self.headers.get('Content-Length', 0))
                if self.headers.get("Transfer-Encoding") and self.headers.get("Transfer-Encoding") != "identity":
                    if self.rbuffer:
                        self.remotesoc.sendall(b''.join(self.rbuffer))
                    flag = 1
                    req_body_len = 0
                    while flag:
                        trunk_lenth = self.rfile_readline()
                        if self.retryable:
                            self.rbuffer.append(trunk_lenth)
                            req_body_len += len(trunk_lenth)
                        self.remotesoc.sendall(trunk_lenth)
                        trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                        flag = trunk_lenth != 2
                        data = self.rfile_read(trunk_lenth)
                        if self.retryable:
                            self.rbuffer.append(data)
                            req_body_len += len(data)
                        self.remotesoc.sendall(data)
                        if req_body_len > 102400:
                            self.retryable = False
                            self.rbuffer = deque()
                elif content_length > 0:
                    if content_length > 102400:
                        self.retryable = False
                    if self.rbuffer:
                        s = b''.join(self.rbuffer)
                        content_length -= len(s)
                        self.remotesoc.sendall(s)
                    while content_length:
                        data = self.rfile_read(min(self.bufsize, content_length))
                        if not data:
                            break
                        content_length -= len(data)
                        if self.retryable:
                            self.rbuffer.append(data)
                        self.remotesoc.sendall(data)
                # read response line
                timelog = time.clock()
                self.phase = 'reading response_line'
                response_line, protocol_version, response_status, response_reason = read_reaponse_line(remoterfile)
                rtime = time.clock() - timelog
            # read response headers
            while response_status == 100:
                hdata = read_header_data(remoterfile)
                self._wfile_write(response_line + hdata)
                response_line, protocol_version, response_status, response_reason = read_reaponse_line(remoterfile)
            self.phase = 'reading response header'
            header_data, response_header = read_headers(remoterfile)
            conntype = response_header.get('Connection', "")
            if protocol_version >= b"HTTP/1.1":
                remote_close = 'close' in conntype.lower()
            else:
                remote_close = 'keep_alive' in conntype.lower()
            if 'Upgrade' in response_header:
                remote_close = True
            if "Content-Length" in response_header:
                if "," in response_header["Content-Length"]:
                    # Proxies sometimes cause Content-Length headers to get
                    # duplicated.  If all the values are identical then we can
                    # use them but if they differ it's an error.
                    pieces = re.split(r',\s*', response_header["Content-Length"])
                    if any(i != pieces[0] for i in pieces):
                        raise ValueError("Multiple unequal Content-Lengths: %r" %
                                         response_header["Content-Length"])
                    response_header["Content-Length"] = pieces[0]
                content_length = int(response_header["Content-Length"])
            else:
                content_length = None
            buf = io.BytesIO(header_data)
            header_data = b''
            for line in buf:
                if line.startswith('Connection') and 'Upgrade' not in line:
                    header_data += b'Connection: close\r\n' if client_close else b'Connection: keep_alive\r\n'
                else:
                    header_data += line
            self.wfile_write(response_line)
            self.wfile_write(header_data)
            # verify
            if response_status in (301, 302) and self.conf.PARENT_PROXY.bad302(response_header.get('Location')):
                raise IOError(0, 'Bad 302!')
            # read response body
            self.phase = 'reading response body'
            if self.command == 'HEAD' or response_status in (204, 205, 304):
                pass
            elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
                flag = 1
                while flag:
                    trunk_lenth = remoterfile.readline()
                    self.wfile_write(trunk_lenth)
                    trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                    flag = trunk_lenth != 2
                    while trunk_lenth:
                        data = self.remotesoc.recv(min(self.bufsize, trunk_lenth))
                        trunk_lenth -= len(data)
                        self.wfile_write(data)
            elif content_length is not None:
                while content_length:
                    data = self.remotesoc.recv(min(self.bufsize, content_length))
                    if not data:
                        raise IOError(0, 'remote socket closed')
                    content_length -= len(data)
                    self.wfile_write(data)
            else:
                # websocket?
                self.close_connection = 1
                self.retryable = False
                self.wfile_write()
                fd = [self.connection, self.remotesoc]
                while fd:
                    ins, _, _ = select.select(fd, [], [], 60)
                    if not ins:
                        break
                    if self.connection in ins:
                        data = self.connection_recv(self.bufsize)
                        if data:
                            self.remotesoc.sendall(data)
                        else:
                            fd.remove(self.connection)
                            self.remotesoc.shutdown(socket.SHUT_WR)
                    if self.remotesoc in ins:
                        data = self.remotesoc.recv(self.bufsize)
                        if data:
                            self._wfile_write(data)
                        else:
                            fd.remove(self.remotesoc)
                            self.connection.shutdown(socket.SHUT_WR)
            self.wfile_write()
            self.phase = 'request finish'
            self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, True if response_status < 400 else False, self.failed_parents, self.ppname, rtime)
            if remote_close or is_connection_dropped([self.remotesoc]):
                self.remotesoc.close()
            else:
                self.HTTPCONN_POOL.put(self.upstream_name, self.remotesoc, self.ppname if '(pooled)' in self.ppname else (self.ppname + '(pooled)'))
            self.remotesoc = None
        except ClientError as e:
            raise
        except NetWorkIOError as e:
            return self.on_GET_Error(e)

    def on_GET_Error(self, e):
        if self.ppname:
            self.logger.warning('{} {} via {} failed: {}! {}'.format(self.command, self.shortpath, self.ppname, self.phase, repr(e)))
            return self._do_GET(True)
        self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
        return self.send_error(504)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = do_GET

    def do_CONNECT(self):
        self.close_connection = 1
        host, _, port = self.path.partition(':')
        self.requesthost = (host, int(port))
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')

        if 'Host' not in self.headers:
            self.headers['Host'] = self.path
        # redirector
        new_url = self.conf.PARENT_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s' % (new_url, self.command, self.path))
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                return self.send_error(int(new_url))
            elif new_url.lower() in ('reset', 'adblock'):
                return
            elif all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                random.shuffle(self._proxylist)

        ip = self.conf.resolver.get_ip_address(self.requesthost[0])

        if ip.is_loopback or self.ssclient:
            if ip_address(self.client_address[0]).is_loopback:
                if self.requesthost[1] in range(self.conf.listen[1], self.conf.listen[1] + self.conf.profiles):
                    # prevent loop
                    return self.send_error(403)
            else:
                return self.send_error(403, 'Go fuck yourself!')
        self.wfile.write(self.protocol_version.encode() + b" 200 Connection established\r\n\r\n")
        self._do_CONNECT()

    def _do_CONNECT(self, retry=False):
        if retry:
            self.failed_parents.append(self.ppname)
        if self.remotesoc:
            self.remotesoc.close()
        if not self.retryable or self.getparent():
            self.conf.PARENT_PROXY.notify(self.command, self.path, self.path, False, self.failed_parents, self.ppname)
            return
        iplist = None
        if self.pproxy.name == 'direct' and self.requesthost[0] in self.conf.HOSTS and not self.failed_parents:
            iplist = self.conf.HOSTS.get(self.requesthost[0])
            self._proxylist.insert(0, self.pproxy)
        self.set_timeout()
        self.phase = 'connect'
        try:
            self.remotesoc = self._connect_via_proxy(self.requesthost, iplist, tunnel=True)
            self.remotesoc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except NetWorkIOError as e:
            self.logger.warning('%s %s via %s failed on connect! %r' % (self.command, self.path, self.ppname, e))
            return self._do_CONNECT(True)
        count = 0
        if self.rbuffer:
            self.logger.debug('remote write rbuffer')
            self.remotesoc.sendall(b''.join(self.rbuffer))
            count = 1
            timelog = time.clock()
        rtime = 0
        while 1:
            try:
                reason = ''
                (ins, _, _) = select.select([self.connection, self.remotesoc], [], [], self.conf.timeout)
                if not ins:
                    reason = 'timeout'
                    break
                if self.connection in ins:
                    self.phase = 'read from client'
                    data = self.connection_recv(self.bufsize)
                    if not data:
                        reason = 'client closed'
                        self.remotesoc.shutdown(socket.SHUT_WR)
                        break
                    self.remotesoc.sendall(data)
                    # Now remotesoc is connected, set read timeout
                    self.remotesoc.settimeout(self.rtimeout)
                    count += 1
                    timelog = time.clock()
                    if self.retryable:
                        self.rbuffer.append(data)
                if self.remotesoc in ins:
                    self.phase = 'read from remote'
                    data = self.remotesoc.recv(self.bufsize)
                    if not data:  # remote connection closed
                        reason = 'remote closed'
                        break
                    rtime = time.clock() - timelog
                    self._wfile_write(data)
            except NetWorkIOError as e:
                self.logger.warning('do_CONNECT error: %r on %s %s' % (e, self.phase, count))
                break
        if self.rbuffer and self.rbuffer[0].startswith((b'\x16\x03\x00', b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03')) and count < 2:
            if reason != 'client closed' and self.phase != 'read from client':
                self.logger.warning('TLS key exchange failed? hostname: %s, %s %s %s' % (self.requesthost[0], self.phase, count, reason))
        if self.retryable:
            reason = reason or "don't know why"
            if reason != 'client closed' and self.phase != 'read from client':
                self.logger.warning('%s %s via %s failed on %s! %s' % (self.command, self.path, self.ppname, self.phase, reason))
            return self._do_CONNECT(True)
        self.rbuffer = deque()
        self.conf.PARENT_PROXY.notify(self.command, self.path, self.requesthost, True, self.failed_parents, self.ppname, rtime)
        """forward socket"""
        try:
            fd = [self.connection, self.remotesoc]
            while fd:
                ins, _, _ = select.select(fd, [], [], 60)
                if not ins:
                    break
                if self.connection in ins:
                    data = self.connection_recv(self.bufsize)
                    if data:
                        self.remotesoc.sendall(data)
                    else:
                        fd.remove(self.connection)
                        self.remotesoc.shutdown(socket.SHUT_WR)
                if self.remotesoc in ins:
                    data = self.remotesoc.recv(self.bufsize)
                    if data:
                        self._wfile_write(data)
                    else:
                        fd.remove(self.remotesoc)
                        self.connection.shutdown(socket.SHUT_WR)
        except socket.timeout:
            pass
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            for sock in [self.connection, self.remotesoc]:
                try:
                    sock.close()
                except NetWorkIOError:
                    pass

    def on_conn_log(self):
        if self.ssclient:
            self.logmethod('{} {} via {} client: {} {}'.format(self.command, self.shortpath or self.path, self.ppname, self.ssclient, self.ssrealip))
        else:
            self.logmethod('{} {} via {}'.format(self.command, self.shortpath or self.path, self.ppname))

    def wfile_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
                self.remotesoc.settimeout(10)
        else:
            if self.wbuffer:
                self._wfile_write(b''.join(self.wbuffer))
                self.wbuffer = deque()
            if data:
                self._wfile_write(data)

    def set_timeout(self):
        if self._proxylist:
            if self.ppname == 'direct':
                self.rtimeout = self.conf.timeout
                self.ctimeout = self.conf.timeout
            else:
                self.rtimeout = min(2 ** len(self.failed_parents) + self.conf.timeout, 20)
                self.ctimeout = min(2 ** len(self.failed_parents) + self.conf.timeout, 20)
        else:
            self.ctimeout = self.rtimeout = 20

    def _http_connect_via_proxy(self, netloc, iplist):
        if not self.failed_parents:
            result = self.HTTPCONN_POOL.get(self.upstream_name)
            if result:
                self._proxylist.insert(0, self.conf.parentlist.get(self.ppname))
                sock, self.ppname = result
                self.on_conn_log()
                return sock
        return self._connect_via_proxy(netloc, iplist)

    def _connect_via_proxy(self, netloc, iplist=None, tunnel=False):
        self.on_conn_log()
        return create_connection(netloc, ctimeout=self.ctimeout, iplist=iplist, parentproxy=self.pproxy, tunnel=tunnel)

    def do_FTP(self):
        self.logger.info('{} {}'.format(self.command, self.path))
        # fish out user and password information
        p = urlparse.urlparse(self.path, 'http')
        user, passwd = p.username or "anonymous", p.password or None
        if self.command == "GET":
            if p.path.endswith('/'):
                return self.do_FTP_LIST(p.netloc, urlunquote(p.path), user, passwd)
            else:
                try:
                    ftp = ftplib.FTP(p.netloc)
                    ftp.login(user, passwd)
                    lst = []
                    response = ftp.retrlines("LIST %s" % urlunquote(p.path), lst.append)
                    if not lst:
                        return self.send_error(504, response)
                    if len(lst) != 1 or lst[0].startswith('d'):
                        return self.redirect('%s/' % self.path)
                    self.send_response(200)
                    self.send_header('Content-Length', lst[0].split()[4])
                    self.send_header('Connection', 'keep_alive')
                    self.end_headers()
                    ftp.retrbinary("RETR %s" % urlunquote(p.path), self._wfile_write, self.bufsize)
                    ftp.quit()
                except Exception as e:  # Possibly no such file
                    self.logger.warning("FTP Exception: %r" % e)
                    self.send_error(504, repr(e))
        else:
            self.send_error(501)

    def do_FTP_LIST(self, netloc, path, user, passwd):
        if not path.endswith('/'):
            self.path += '/'
        lst = []
        table = '<table class="content"><thead><tr><th align="left">Content</th><th align="right">Size</th><th align="right">Modify</th></tr></thead><tbody>'
        try:
            ftp = ftplib.FTP(netloc)
            ftp.login(user, passwd)
            response = ftp.retrlines("LIST %s" % path, lst.append)
            ftp.quit()
            for line in lst:
                self.logger.debug(line)
                line_split = line.split(None, 8)
                if line.startswith('d'):
                    line_split[8] += '/'
                table += '<tr><td align="left"><a href="%s%s">%s</a></td><td align="right">%s</td><td align="right">%s %s %s</td></tr>\r\n' % (
                    self.path, urlquote(line_split[8]), line_split[8], line_split[4] if line.startswith('d') else sizeof_fmt(int(line_split[4])), line_split[5], line_split[6], line_split[7])
            table += '<tr><td align="left">================</td><td align="right">==========</td><td align="right">=============</td></tr></tbody></table>\r\n'
            table += '<p>%s</p>' % response
        except Exception as e:
            self.logger.warning("FTP Exception: %r" % e)
            self.send_error(504, repr(e))
        else:
            msg = ['<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>\n',
                   '<head><style type="text/css">.content tr{font-family:Consolas,"Droid Sans Mono", Menlo, Monospace;}</style></head>',
                   "<title>Directory listing for %s</title>\n" % path,
                   "<body>\n<h2>Directory listing for %s</h2>\n<hr>\n" % path,
                   table,
                   "<hr>\n</body>\n</html>\n"]
            self.write(200, ''.join(msg), 'text/html')

    def api(self, parse):
        '''
        path: supported command
        /api/localrule: GET POST DELETE
        '''
        self.logger.debug('{} {}'.format(self.command, self.path))
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 102400:
            return
        body = StringIO()
        while content_length:
            data = self.rfile_read(min(self.bufsize, content_length))
            if not data:
                return
            content_length -= len(data)
            body.write(data)
        body = body.getvalue()
        if parse.path == '/api/localrule' and self.command == 'GET':
            data = json.dumps([(rule, self.conf.PARENT_PROXY.local.expire[rule]) for rule in self.conf.PARENT_PROXY.local.rules])
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/localrule' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, int exp)'
            rule, exp = json.loads(body)
            result = self.conf.PARENT_PROXY.add_temp(rule, exp)
            self.write(400 if result else 201, result, 'application/json')
            return self.conf.stdout()
        elif parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = base64.urlsafe_b64decode(parse.path[15:].encode('latin1'))
                expire = self.conf.PARENT_PROXY.local.remove(rule)
                self.write(200, json.dumps([rule, expire]), 'application/json')
                return self.conf.stdout()
            except Exception as e:
                sys.stderr.write(traceback.format_exc() + '\n')
                sys.stderr.flush()
                return self.send_error(404, repr(e))
        elif parse.path == '/api/redirector' and self.command == 'GET':
            data = json.dumps([(index, rule[0].rule, rule[1]) for index, rule in enumerate(self.conf.REDIRECTOR.redirlst)])
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/redirector' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, str dest)'
            rule, dest = json.loads(body)
            self.conf.PARENT_PROXY.add_redirect(rule, dest)
            self.write(200, data, 'application/json')
            return self.conf.stdout()
        elif parse.path.startswith('/api/redirector/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                if rule:
                    assert base64.urlsafe_b64decode(rule) == self.conf.REDIRECTOR.redirlst[int(parse.path[16:])][0].rule
                rule, dest = self.conf.REDIRECTOR.redirlst.pop(int(parse.path[16:]))
                self.write(200, json.dumps([int(parse.path[16:]), rule.rule, dest]), 'application/json')
                return self.conf.stdout()
            except Exception as e:
                return self.send_error(404, repr(e))
        elif parse.path == '/api/parent' and self.command == 'GET':
            data = [(p.name, ('%s://%s:%s' % (p.scheme, p.hostname, p.port)) if p.proxy else '', p.httppriority) for k, p in self.conf.parentlist.dict.items()]
            data = sorted(data, key=lambda item: item[0])
            data = json.dumps(sorted(data, key=lambda item: item[2]))
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/parent' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, str dest)'
            name, proxy = json.loads(body)
            if proxy.startswith('ss://') and self.conf.userconf.has_option('parents', 'shadowsocks_0'):
                self.conf.userconf.remove_option('parents', 'shadowsocks_0')
            self.conf.parentlist.remove('shadowsocks_0')
            self.conf.addparentproxy(name, proxy)
            self.conf.userconf.set('parents', name, proxy)
            self.conf.confsave()
            self.write(200, data, 'application/json')
            return self.conf.stdout()
        elif parse.path.startswith('/api/parent/') and self.command == 'DELETE':
            try:
                self.conf.parentlist.remove(parse.path[12:])
                if self.conf.userconf.has_option('parents', parse.path[12:]):
                    self.conf.userconf.remove_option('parents', parse.path[12:])
                    self.conf.confsave()
                self.write(200, parse.path[12:], 'application/json')
                return self.conf.stdout()
            except Exception as e:
                return self.send_error(404, repr(e))
        elif parse.path == '/api/gfwlist' and self.command == 'GET':
            return self.write(200, json.dumps(self.conf.userconf.dgetbool('fgfwproxy', 'gfwlist', True)), 'application/json')
        elif parse.path == '/api/gfwlist' and self.command == 'POST':
            self.conf.userconf.set('fgfwproxy', 'gfwlist', '1' if json.loads(body) else '0')
            self.conf.confsave()
            self.write(200, data, 'application/json')
            return self.conf.stdout()
        elif parse.path == '/api/autoupdate' and self.command == 'GET':
            return self.write(200, json.dumps(self.conf.userconf.dgetbool('FGFW_Lite', 'autoupdate', True)), 'application/json')
        elif parse.path == '/api/autoupdate' and self.command == 'POST':
            self.conf.userconf.set('FGFW_Lite', 'autoupdate', '1' if json.loads(body) else '0')
            self.conf.confsave()
            self.write(200, data, 'application/json')
            return self.conf.stdout()
        elif parse.path == '/' and self.command == 'GET':
            return self.write(200, 'Hello World !', 'text/html')
        self.send_error(404)


def updater(conf):
    lastupdate = conf.version.dgetfloat('Update', 'LastUpdate', 0)
    if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
        try:
            update(conf, auto=True)
        except:
            conf.logger.error(traceback.format_exc())
    Timer(random.randint(600, 3600), updater, (conf, )).start()


def update(conf, auto=False):
    if auto and not conf.userconf.dgetbool('FGFW_Lite', 'autoupdate'):
        return
    gfwlist_url = conf.userconf.dget('fgfwproxy', 'gfwlist_url', 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt')

    filelist = [(gfwlist_url, './fgfw-lite/gfwlist.txt'), ]

    adblock_url = conf.userconf.dget('fgfwproxy', 'adblock_url', '')
    if adblock_url:
        filelist.append((adblock_url, './fgfw-lite/adblock.txt'))

    for url, path in filelist:
        etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
        req = urllib2.Request(url)
        if etag:
            req.add_header('If-None-Match', etag)
        try:
            r = urllib2.urlopen(req)
        except Exception as e:
            if isinstance(e, urllib2.HTTPError):
                conf.logger.info('%s NOT updated: %s' % (path, e.reason))
            else:
                conf.logger.info('%s NOT updated: %r' % (path, e))
        else:
            data = r.read()
            if r.getcode() == 200 and data:
                with open(path, 'wb') as localfile:
                    localfile.write(data)
                etag = r.info().getheader('ETag')
                if etag:
                    conf.version.set('Update', path.replace('./', '').replace('/', '-'), etag)
                    conf.confsave()
                conf.logger.info('%s Updated.' % path)
            else:
                conf.logger.info('{} NOT updated: {}'.format(path, str(r.getcode())))
    branch = conf.userconf.dget('FGFW_Lite', 'branch', 'master')
    count = 0
    try:
        r = json.loads(urllib2.urlopen('https://github.com/v3aqb/fwlite/raw/%s/fgfw-lite/update.json' % branch).read())
    except Exception as e:
        conf.logger.info('read update.json failed: %r' % e)
    else:
        import hashlib
        update = {}
        success = 1
        for path, v, in r.items():
            try:
                if v == conf.version.dget('Update', path.replace('./', '').replace('/', '-'), ''):
                    conf.logger.debug('{} Not Modified'.format(path))
                    continue
                conf.logger.info('Update: Downloading %s...' % path)
                fdata = urllib2.urlopen('https://github.com/v3aqb/fwlite/raw/%s%s' % (branch, path[1:])).read()
                h = hashlib.new("sha256", fdata).hexdigest()
                if h != v:
                    conf.logger.warning('%s NOT updated: hash mismatch. %s %s' % (path, h, v))
                    success = 0
                    break
                update[path] = (fdata, h)
                conf.logger.info('%s Downloaded.' % path)
            except Exception as e:
                success = 0
                conf.logger.error('update failed: %r\n%s' % (e, traceback.format_exc()))
                break
        if success:
            for path, v in update.items():
                try:
                    fdata, h = v
                    if not os.path.isdir(os.path.dirname(path)):
                        os.mkdir(os.path.dirname(path))
                    with open(path, 'wb') as localfile:
                        localfile.write(fdata)
                    conf.logger.info('%s Updated.' % path)
                    conf.version.set('Update', path.replace('./', '').replace('/', '-'), h)
                    if not path.endswith(('txt', 'ini')):
                        count += 1
                except:
                    sys.stderr.write(traceback.format_exc() + '\n')
                    sys.stderr.flush()
        else:
            conf.logger.error('update failed!')
        conf.version.set('Update', 'LastUpdate', str(time.time()))
    conf.confsave()
    if not conf.GUI:
        for item in FGFWProxyHandler.ITEMS:
            item.restart()
    conf.PARENT_PROXY.config()
    if count:
        conf.logger.info('Update Completed, %d file Updated.' % count)
    if conf.userconf.dget('FGFW_Lite', 'updatecmd', ''):
        subprocess.Popen(shlex.split(conf.userconf.dget('FGFW_Lite', 'updatecmd', '')))


class FGFWProxyHandler(object):
    """docstring for FGFWProxyHandler"""
    ITEMS = []

    def __init__(self, conf):
        FGFWProxyHandler.ITEMS.append(self)
        self.conf = conf
        self.logger = self.conf.logger
        self.subpobj = None
        self.cmd = ''
        self.cwd = ''
        self.pid = None
        self.filelist = []
        self.enable = True
        self.start()

    def config(self):
        pass

    def start(self):
        try:
            self.config()
            if self.enable:
                self.logger.info('starting %s' % self.cmd)
                self.subpobj = subprocess.Popen(shlex.split(self.cmd), cwd=self.cwd, stdin=subprocess.PIPE)
                self.pid = self.subpobj.pid
        except Exception:
            sys.stderr.write(traceback.format_exc() + '\n')
            sys.stderr.flush()

    def restart(self):
        self.stop()
        self.start()

    def stop(self):
        try:
            self.subpobj.terminate()
        except:
            pass
        finally:
            self.subpobj = None


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()


def main():
    s = 'FWLite ' + __version__
    if gevent:
        s += ' with gevent %s' % gevent.__version__
    logging.info(s)
    conf = config.conf
    Timer(10, updater, (conf, )).start()
    d = {'http': '127.0.0.1:%d' % conf.listen[1], 'https': '127.0.0.1:%d' % conf.listen[1]}
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler(d)))
    for i, level in enumerate(list(conf.userconf.dget('fgfwproxy', 'profile', '13'))):
        server = ThreadingHTTPServer((conf.listen[0], conf.listen[1] + i), ProxyHandler, conf=conf, level=int(level))
        t = Thread(target=server.serve_forever)
        t.start()

    if conf.userconf.dgetbool('dns', 'enable', False):
        try:
            listen = parse_hostport(conf.userconf.dget('dns', 'listen', '127.0.0.1:53'))
            from dnsserver import Resolver, UDPDNSServer, DNSHandler, TCPDNSServer
            r = Resolver(conf.resolver)
            server = UDPDNSServer(listen, DNSHandler, r)
            t2 = Thread(target=server.serve_forever)
            t2.start()
            server = TCPDNSServer(listen, DNSHandler, r)
            t2 = Thread(target=server.serve_forever)
            t2.start()
        except Exception as e:
            logging.error(repr(e))
            logging.error(traceback.format_exc() + '\n')
    conf.stdout()
    t.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
