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

from __future__ import print_function, division

__version__ = '4.3'

import sys
import os
import glob

sys.dont_write_bytecode = True
WORKINGDIR = '/'.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')).split('/')[:-1])
if ' ' in WORKINGDIR:
    sys.stderr.write('no spacebar allowed in path\n')
    sys.exit(-1)
os.chdir(WORKINGDIR)
sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))
sys.path += glob.glob('%s/goagent/*.egg' % WORKINGDIR)
gevent = None
try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    pass
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('Warning: Please update gevent to the latest 1.0 version!\n')
from collections import defaultdict, deque
import copy
import subprocess
import shlex
import time
import re
import datetime
import errno
import email
import atexit
import base64
import itertools
import json
import ftplib
import logging
import random
import select
import shutil
import socket
import struct
import ssl
import sqlite3
import traceback
import pygeoip
try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import BytesIO as StringIO
from threading import Thread, RLock
from repoze.lru import lru_cache
import encrypt
from util import create_connection, parse_hostport, is_connection_dropped, get_ip_address, SConfigParser, sizeof_fmt
try:
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ipaddress import ip_address
except ImportError:
    import urllib2
    import urlparse
    urlquote = urllib2.quote
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from ipaddr import IPAddress as ip_address

logging.basicConfig(level=logging.INFO,
                    format='FGFW-Lite %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')

if sys.platform.startswith('win'):
    PYTHON2 = '%s/Python27/python27.exe' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break

ctimer = []
CTIMEOUT = 5
NetWorkIOError = (socket.error, ssl.SSLError, OSError)


def prestart():
    s = 'FGFW_Lite ' + __version__
    if gevent:
        s += ' with gevent %s' % gevent.__version__
    logging.info(s)

    if not os.path.isfile('./userconf.ini'):
        shutil.copyfile('./userconf.sample.ini', './userconf.ini')

    if not os.path.isfile('./fgfw-lite/local.txt'):
        with open('./fgfw-lite/local.txt', 'w') as f:
            f.write('''
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

prestart()


class stats(object):
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("create table log (timestamp real, date text, command text, hostname text, url text, ppname text, success integer)")

    def log(self, command, hostname, url, ppname, success):
        with self.con:
            self.con.execute('insert into log values (?,?,?,?,?,?,?)', (time.time(), datetime.date.today(), command, hostname, url, ppname, success))

    def srbh(self, hostname, sincetime=None):
        '''success rate by hostname'''
        if sincetime is None:
            sincetime = time.time() - 24 * 60 * 60
        r = self.con.execute('select count(*), sum(success) from log where hostname = (?) and timestamp >= (?)', (hostname, sincetime)).next()
        if r[0] == 0:
            return(0, 0)
        return (r[1] / r[0], r[0])

    def srbp(self, ppname, sincetime=None):
        '''success rate by ppname'''
        if sincetime is None:
            sincetime = time.time() - 24 * 60 * 60
        r = self.con.execute('select count(*), sum(success) from log where ppname = (?) and timestamp >= (?)', (ppname, sincetime)).next()
        if r[0] == 0:
            return(0, 0)
        return (r[1] / r[0], r[0])

    def srbhp(self, hostname, ppname, sincetime=None):
        '''success rate by hostname and ppname'''
        if sincetime is None:
            sincetime = time.time() - 24 * 60 * 60
        r = self.con.execute('select count(*), sum(success) from log where hostname = (?) and ppname = (?) and timestamp >= (?)', (hostname, ppname, sincetime)).next()
        if r[0] == 0:
            return(0, 0)
        return (r[1] / r[0], r[0])

    def purge(self, befortime=None):
        if not befortime:
            befortime = time.time() - 24 * 60 * 60
        with self.con:
            self.con.execute('delete from log where timestamp < ?', (befortime, ))


class httpconn_pool(object):
    POOL = defaultdict(deque)
    timerwheel = defaultdict(list)
    timerwheel_index_iter = itertools.cycle(range(10))
    timerwheel_index = next(timerwheel_index_iter)
    lock = RLock()

    def __init__(self, logger=logging):
        self.logger = logger

    def put(self, upstream_name, soc, ppname):
        with self.lock:
            self.POOL[upstream_name].append((soc, ppname))
            self.timerwheel[self.timerwheel_index].append((upstream_name, (soc, ppname)))

    def get(self, upstream_name):
        lst = self.POOL.get(upstream_name)
        with self.lock:
            while lst:
                sock, pproxy = lst.popleft()
                if not is_connection_dropped(sock):
                    return (sock, pproxy)
                sock.close()

    def purge(self):
        pcount = count = 0
        with self.lock:
            for k, v in self.POOL.items():
                count += len(v)
                for i in [pair for pair in v if pair[0] in select.select([item[0] for item in v], [], [], 0.0)[0]]:
                    i[0].close()
                    v.remove(i)
                    pcount += 1
            self.timerwheel_index = next(self.timerwheel_index_iter)
            for upsname, soc in self.timerwheel[self.timerwheel_index]:
                if soc in self.POOL[upsname]:
                    soc[0].close()
                    self.POOL[upsname].remove(soc)
                    pcount += 1
            self.timerwheel[self.timerwheel_index] = []
        count -= pcount
        if pcount:
            self.logger.info('%d remotesoc purged, %d in connection pool.(%s)' % (pcount, count, ', '.join([k[0] if isinstance(k, tuple) else k for k, v in self.POOL.items() if v])))


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, level=1, conf=None):
        self.proxy_level = level
        self.conf = conf
        self.logger = self.conf.logger
        self.logger.info('starting server at %s:%s, level %d' % (server_address[0], server_address[1], level))
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.conf = server.conf
        self.logger = server.logger
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
        except (IOError, OSError) as e:
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
            self.wfile.write(content)

    def write(self, code=200, msg=None, ctype=None):
        if msg is None:
            msg = ''
        self.send_response(code)
        if ctype:
            self.send_header('Content-type', ctype)
        self.send_header('Content-Length', str(len(msg)))
        self.send_header('Connection', 'keep_alive')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(msg)

    def _request_is_localhost(self, req):
        try:
            return get_ip_address(req[0], req[1]).is_loopback
        except Exception:
            pass


class ProxyHandler(HTTPRequestHandler):
    server_version = "FGFW-Lite/" + __version__
    protocol_version = "HTTP/1.1"
    bufsize = 8192
    timeout = 10

    def handle_one_request(self):
        self._proxylist = None
        self.remotesoc = None
        self.retryable = True
        self.rbuffer = deque()  # client read buffer: store request body, ssl handshake package for retry. no pop method.
        self.wbuffer = deque()  # client write buffer: read only once, not used in connect method
        self.wbuffer_size = 0
        self.shortpath = None
        self.failed_parents = []
        try:
            HTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            if e.errno in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                self.close_connection = 1
            else:
                raise
        if self.remotesoc:
            self.remotesoc.close()

    def getparent(self):
        if self._proxylist is None:
            self._proxylist = self.conf.PARENT_PROXY.parentproxy(self.path, self.requesthost, self.command, self.server.proxy_level)
            self.logger.debug(repr(self._proxylist))
        if not self._proxylist:
            self.ppname = ''
            return 1
        self.pproxy = self._proxylist.pop(0)
        self.ppname = self.pproxy.name
        self.pproxyparse = self.pproxy.parse

    def do_GET(self):
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            return self.do_FTP()
        # transparent proxy
        if self.path.startswith('/') and 'Host' in self.headers:
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)
        if self.path.startswith('/'):
            return self.send_error(403)
        # redirector
        new_url = self.conf.PARENT_PROXY.redirect(self.path)
        if new_url:
            self.logger.debug('redirecting to %s' % new_url)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                return self.send_error(int(new_url))
            elif new_url in self.conf.parentlist.dict.keys():
                self._proxylist = [self.conf.parentlist.dict.get(new_url)]
            else:
                return self.redirect(new_url)

        parse = urlparse.urlparse(self.path)

        if 'Host' not in self.headers:
            self.headers['Host'] = parse.netloc

        self.requesthost = parse_hostport(self.headers['Host'], 80)

        if self._request_is_localhost(self.requesthost):
            if ip_address(self.client_address[0]).is_loopback and self.requesthost[1] in (self.conf.listen[1], self.conf.listen[1] + 1, self.conf.listen[1] + 2):
                return self.api(parse)
            if not ip_address(self.client_address[0]).is_loopback:
                return self.send_error(403)

        self.shortpath = '%s://%s%s%s%s' % (parse.scheme, parse.netloc, parse.path.split(':')[0], '?' if parse.query else '', ':' if ':' in parse.path else '')

        if self.conf.xheaders:
            ipl = [ip.strip() for ip in self.headers.get('X-Forwarded-For', '').split(',') if ip.strip()]
            ipl.append(self.client_address[0])
            self.headers['X-Forwarded-For'] = ', '.join(ipl)

        self._do_GET()

    def _do_GET(self, retry=False):
        if retry:
            if self.remotesoc:
                self.remotesoc.close()
                self.remotesoc = None
            self.failed_parents.append(self.ppname)
        if not self.retryable:
            self.close_connection = 1
            self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
            return
        if self.getparent():
            self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, False, self.failed_parents, self.ppname)
            return self.send_error(504)

        self.upstream_name = self.ppname if self.pproxy.proxy.startswith('http') else self.requesthost
        try:
            self.remotesoc = self._http_connect_via_proxy(self.requesthost)
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        self.wbuffer = deque()
        self.wbuffer_size = 0
        # send request header
        self.logger.debug('sending request header')
        s = []
        if self.pproxy.proxy.startswith('http'):
            s.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
            if self.pproxyparse.username:
                a = '%s:%s' % (self.pproxyparse.username, self.pproxyparse.password)
                self.headers['Proxy-Authorization'] = 'Basic %s' % base64.b64encode(a.encode())
        else:
            s.append('%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version))
        del self.headers['Proxy-Connection']
        for k, v in self.headers.items():
            if isinstance(v, bytes):
                v = v.decode('latin1')
            s.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in k.split("-")]), v))
        s.append("\r\n")
        try:
            self.remotesoc.sendall(''.join(s).encode('latin1'))
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        self.logger.debug('sending request body')
        # send request body
        content_length = int(self.headers.get('Content-Length', 0))
        if self.headers.get("Transfer-Encoding") and self.headers.get("Transfer-Encoding") != "identity":
            if self.rbuffer:
                try:
                    self.remotesoc.sendall(b''.join(self.rbuffer))
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
            flag = 1
            req_body_len = 0
            while flag:
                trunk_lenth = self.rfile.readline()
                if self.retryable:
                    self.rbuffer.append(trunk_lenth)
                    req_body_len += len(trunk_lenth)
                try:
                    self.remotesoc.sendall(trunk_lenth)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                flag = trunk_lenth != 2
                data = self.rfile.read(trunk_lenth)
                if self.retryable:
                    self.rbuffer.append(data)
                    req_body_len += len(data)
                try:
                    self.remotesoc.sendall(data)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                if req_body_len > 102400:
                    self.retryable = False
                    self.rbuffer = deque()
        elif content_length > 0:
            if content_length > 102400:
                self.retryable = False
            if self.rbuffer:
                s = b''.join(self.rbuffer)
                content_length -= len(s)
                try:
                    self.remotesoc.sendall(s)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
            while content_length:
                data = self.rfile.read(min(self.bufsize, content_length))
                if not data:
                    break
                content_length -= len(data)
                if self.retryable:
                    self.rbuffer.append(data)
                try:
                    self.remotesoc.sendall(data)
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
        # read response line
        self.logger.debug('reading response_line')
        remoterfile = self.remotesoc if hasattr(self.remotesoc, 'readline') else self.remotesoc.makefile('rb', 0)
        try:
            s = response_line = remoterfile.readline()
            if not s.startswith(b'HTTP'):
                raise OSError(0, 'bad response line: %r' % response_line)
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        protocol_version, _, response_status = response_line.rstrip(b'\r\n').partition(b' ')
        response_status, _, response_reason = response_status.partition(b' ')
        response_status = int(response_status)
        # read response headers
        self.logger.debug('reading response header')
        header_data = []
        try:
            while True:
                line = remoterfile.readline()
                header_data.append(line)
                if line in (b'\r\n', b'\n', b'\r'):  # header ends with a empty line
                    break
                if not line:
                    raise OSError(0, 'remote socket closed')
        except NetWorkIOError as e:
            return self.on_GET_Error(e)
        header_data = b''.join(header_data)
        response_header = email.message_from_string(str(header_data))
        conntype = response_header.get('Connection', "")
        if protocol_version >= b"HTTP/1.1":
            self.close_connection = conntype.lower() == 'close'
        else:
            self.close_connection = conntype.lower() != 'keep_alive'
        self.logger.debug('reading response body')
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
        self.wfile_write(s)
        self.wfile_write(header_data)
        # read response body
        if self.command == 'HEAD' or 100 <= response_status < 200 or response_status in (204, 304):
            pass
        elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
            flag = 1
            while flag:
                try:
                    trunk_lenth = remoterfile.readline()
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                self.wfile_write(trunk_lenth)
                trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                flag = trunk_lenth != 2
                while trunk_lenth:
                    try:
                        data = self.remotesoc.recv(min(self.bufsize, trunk_lenth))
                    except NetWorkIOError as e:
                        return self.on_GET_Error(e)
                    trunk_lenth -= len(data)
                    self.wfile_write(data)
        elif content_length is not None:
            while content_length:
                try:
                    data = self.remotesoc.recv(min(self.bufsize, content_length))
                    if not data:
                        raise OSError(0, 'remote socket closed')
                except NetWorkIOError as e:
                    return self.on_GET_Error(e)
                content_length -= len(data)
                self.wfile_write(data)
        else:
            self.close_connection = 1
            self.retryable = False
            while 1:
                try:
                    data = self.remotesoc.recv(self.bufsize)
                    if not data:
                        raise
                    self.wfile_write(data)
                except Exception:
                    break
        self.wfile_write()
        self.logger.debug('request finish')
        self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, True if response_status < 400 else False, self.failed_parents, self.ppname)
        if self.close_connection or is_connection_dropped(self.remotesoc):
            self.remotesoc.close()
        else:
            self.conf.HTTPCONN_POOL.put(self.upstream_name, self.remotesoc, self.ppname if '(pooled)' in self.ppname else self.ppname + '(pooled)')
        self.remotesoc = None

    def on_GET_Error(self, e):
        self.logger.warning('{} {} via {} failed! {}'.format(self.command, self.shortpath, self.ppname, repr(e)))
        return self._do_GET(True)

    do_POST = do_DELETE = do_TRACE = do_HEAD = do_PUT = do_GET

    def do_CONNECT(self):
        self.close_connection = 1
        host, _, port = self.path.partition(':')
        self.requesthost = (host, int(port))
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self._request_is_localhost(self.requesthost):
            if (ip_address(self.client_address[0]).is_loopback and self.requesthost[1] in (self.conf.listen[1], self.conf.listen[1] + 1)) or\
                    not ip_address(self.client_address[0]).is_loopback:
                return self.send_error(403)
        if 'Host' not in self.headers:
            self.headers['Host'] = self.path
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
        try:
            self.remotesoc = self._connect_via_proxy(self.requesthost)
            self.remotesoc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except NetWorkIOError as e:
            self.logger.warning('%s %s via %s failed on connection! %r' % (self.command, self.path, self.ppname, e))
            return self._do_CONNECT(True)

        if self.pproxy.proxy.startswith('http'):
            s = ['%s %s %s\r\n' % (self.command, self.path, self.request_version), ]
            if self.pproxyparse.username:
                a = '%s:%s' % (self.pproxyparse.username, self.pproxyparse.password)
                self.headers['Proxy-Authorization'] = 'Basic %s' % base64.b64encode(a.encode())
            s.append('\r\n'.join(['%s: %s' % (key, value) for key, value in self.headers.items()]))
            s.append('\r\n\r\n')
            self.remotesoc.sendall(''.join(s).encode())
            remoterfile = self.remotesoc.makefile('rb', 0)
            data = remoterfile.readline()
            if b'200' not in data:
                self.logger.warning('{} {} via {} failed! 200 not in response'.format(self.command, self.path, self.ppname))
                return self._do_CONNECT(True)
            while not data in (b'\r\n', b'\n', b'\r'):
                if not data:
                    self.logger.warning('{} {} via {} failed! remote peer closed'.format(self.command, self.path, self.ppname))
                    return self._do_CONNECT(True)
                data = remoterfile.readline()
        if self.rbuffer:
            self.logger.debug('remote write rbuffer')
            self.remotesoc.sendall(b''.join(self.rbuffer))
        while 1:
            try:
                (ins, _, _) = select.select([self.connection, self.remotesoc], [], [], 5)
                if not ins:
                    break
                if self.connection in ins:
                    self.logger.debug('read from client')
                    try:
                        data = self.connection.recv(self.bufsize)
                    except:
                        return
                    if not data:
                        return
                    self.rbuffer.append(data)
                    self.remotesoc.sendall(data)
                if self.remotesoc in ins:
                    self.logger.debug('read from remote')
                    data = self.remotesoc.recv(self.bufsize)
                    if not data:  # remote connection closed
                        self.logger.debug('not data')
                        break
                    self.wfile.write(data)
                    self.logger.debug('self.retryable = False')
                    self.retryable = False
                    break
            except socket.error as e:
                self.logger.warning('socket error: %r' % e)
                break
        if self.retryable:
            self.logger.warning('{} {} via {} failed! read timed out'.format(self.command, self.path, self.ppname))
            return self._do_CONNECT(True)
        self.conf.PARENT_PROXY.notify(self.command, self.path, self.requesthost, True, self.failed_parents, self.ppname)
        self._read_write(self.remotesoc, 300)
        self.remotesoc.close()
        self.connection.close()

    def wfile_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                self.wfile.write(b''.join(self.wbuffer))
                self.wbuffer = deque()
            if data:
                self.wfile.write(data)

    def _http_connect_via_proxy(self, netloc):
        if not self.failed_parents:
            res = self.conf.HTTPCONN_POOL.get(self.upstream_name)
            if res:
                self._proxylist.insert(0, self.conf.parentlist.dict.get(self.ppname))
                sock, self.ppname = res
                self.logger.info('{} {} via {}'.format(self.command, self.shortpath, self.ppname))
                return sock
        return self._connect_via_proxy(netloc)

    def _connect_via_proxy(self, netloc):
        timeout = None if self._proxylist else 20
        self.logger.info('{} {} via {}'.format(self.command, self.shortpath or self.path, self.ppname))
        if not self.pproxy.proxy:
            return create_connection(netloc, timeout or 5)
        elif self.pproxyparse.scheme == 'http':
            return create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 80), timeout or 10)
        elif self.pproxyparse.scheme == 'https':
            s = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 443), timeout or 10)
            s = ssl.wrap_socket(s)
            s.do_handshake()
            return s
        elif self.pproxyparse.scheme == 'ss':
            s = sssocket(self.pproxy.proxy, timeout, self.conf.parentlist.dict.get('direct').proxy)
            s.connect(netloc)
            return s
        elif self.pproxyparse.scheme == 'sni':
            return create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 443), timeout or 10)
        elif self.pproxyparse.scheme == 'socks5':
            s = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 1080), timeout or 10)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"\x05\x02\x00\x02" if self.pproxyparse.username else b"\x05\x01\x00")
            data = s.recv(2)
            if data == b'\x05\x02':  # basic auth
                s.sendall(b''.join([b"\x01",
                                    chr(len(self.pproxyparse.username)).encode(),
                                    self.pproxyparse.username.encode(),
                                    chr(len(self.pproxyparse.password)).encode(),
                                    self.pproxyparse.password.encode()]))
                data = s.recv(2)
            assert data[1] == b'\x00'  # no auth needed or auth passed
            s.sendall(b''.join([b"\x05\x01\x00\x03",
                                chr(len(netloc[0])).encode(),
                                netloc[0].encode(),
                                struct.pack(b">H", netloc[1])]))
            data = s.recv(4)
            assert data[1] == b'\x00'
            if data[3] == b'\x01':  # read ipv4 addr
                s.recv(4)
            elif data[3] == b'\x03':  # read host addr
                s.recv(ord(s.recv(1)))
            elif data[3] == b'\x04':  # read ipv6 addr
                s.recv(16)
            s.recv(2)  # read port
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return s
        raise IOError(0, '_connect_via_proxy failed!')

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        count = 0
        while True:
            try:
                (ins, _, _) = select.select(iw, [], [], 1)
                for i in ins:
                    data = i.recv(self.bufsize)
                    if data:
                        method = self.wfile.write if i is soc else soc.sendall
                        method(data)
                        count = 0
                    elif count < max_idling:
                        count = max_idling  # make sure all data are read before we close the sockets
                if count > max_idling:
                    break
                count += 1
            except socket.error as e:
                self.logger.debug('socket error: %s' % e)
                break

    def do_FTP(self):
        self.logger.info('{} {}'.format(self.command, self.path))
        # fish out user and password information
        p = urlparse.urlparse(self.path, 'http')
        user, passwd = p.username or "anonymous", p.password or None
        if self.command == "GET":
            if p.path.endswith('/'):
                return self.do_FTP_LIST(p.netloc, p.path, user, passwd)
            else:
                try:
                    ftp = ftplib.FTP(p.netloc)
                    ftp.login(user, passwd)
                    lst = []
                    response = ftp.retrlines("LIST %s" % p.path, lst.append)
                    if not lst:
                        return self.send_error(504, response)
                    if len(lst) != 1 or lst[0].startswith('d'):
                        return self.redirect('%s/' % self.path)
                    self.send_response(200)
                    self.send_header('Content-Length', lst[0].split()[4])
                    self.send_header('Connection', 'keep_alive')
                    self.end_headers()
                    ftp.retrbinary("RETR %s" % p.path, self.wfile.write, self.bufsize)
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
                line_split = line.split()
                if line.startswith('d'):
                    line_split[8] += '/'
                table += '<tr><td align="left"><a href="%s%s">%s</a></td><td align="right">%s</td><td align="right">%s %s %s</td></tr>\r\n' % (self.path, line_split[8], line_split[8], line_split[4] if line.startswith('d') else sizeof_fmt(int(line_split[4])), line_split[5], line_split[6], line_split[7])
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
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 102400:
            return
        body = StringIO()
        while content_length:
            data = self.rfile.read(min(self.bufsize, content_length))
            if not data:
                return
            content_length -= len(data)
            body.write(data)
        body = body.getvalue()
        if parse.path == '/api/localrule' and self.command == 'GET':
            data = json.dumps([(index, rule.rule, rule.expire) for index, rule in enumerate(self.conf.PARENT_PROXY.gfwlist_force)])
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/localrule' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, int exp)'
            rule, exp = json.loads(body)
            result = self.conf.PARENT_PROXY.add_temp(rule, exp)
            return self.write(400 if result else 201, result, 'application/json')
        elif parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                if rule:
                    assert base64.urlsafe_b64decode(rule) == self.conf.PARENT_PROXY.gfwlist_force[int(parse.path[15:])].rule
                result = self.conf.PARENT_PROXY.gfwlist_force.pop(int(parse.path[15:]))
                return self.write(200, json.dumps([int(parse.path[15:]), result.rule, result.expire]), 'application/json')
            except Exception as e:
                return self.send_error(404, repr(e))
        elif parse.path == '/api/redirector' and self.command == 'GET':
            data = json.dumps([(index, rule[0].rule, rule[1]) for index, rule in enumerate(self.conf.PARENT_PROXY.redirlst)])
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/redirector' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, str dest)'
            rule, dest = json.loads(body)
            self.conf.PARENT_PROXY.add_rule('%s %s' % (rule, dest))
            return self.write(200, data, 'application/json')
        elif parse.path.startswith('/api/redirector/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                if rule:
                    assert base64.urlsafe_b64decode(rule) == self.conf.PARENT_PROXY.redirlst[int(parse.path[16:])][0].rule
                rule, dest = self.conf.PARENT_PROXY.redirlst.pop(int(parse.path[16:]))
                return self.write(200, json.dumps([int(parse.path[16:]), rule.rule, dest]), 'application/json')
            except Exception as e:
                return self.send_error(404, repr(e))
        elif parse.path == '/api/goagent/pid' and self.command == 'GET':
            data = json.dumps(self.conf.goagent.pid)
            return self.write(200, data, 'application/json')
        elif parse.path == '/' and self.command == 'GET':
            return self.write(200, 'Hello World !', 'text/html')
        self.send_error(404)


class sssocket(object):
    bufsize = 8192

    def __init__(self, ssServer, timeout=10, parentproxy=''):
        self.ssServer = ssServer
        self.timeout = timeout
        self.parentproxy = parentproxy
        self.pproxyparse = urlparse.urlparse(parentproxy)
        self._sock = None
        self.crypto = None
        self.__remote = None
        self.connected = False
        self.__rbuffer = StringIO()

    def connect(self, address):
        self.__address = address
        p = urlparse.urlparse(self.ssServer)
        sshost, ssport, ssmethod, sspassword = (p.hostname, p.port, p.username, p.password)
        self.crypto = encrypt.Encryptor(sspassword, ssmethod)
        if not self.parentproxy:
            self._sock = create_connection((sshost, ssport), self.timeout)
        elif self.parentproxy.startswith('http://'):
            self._sock = create_connection((self.pproxyparse.hostname, self.pproxyparse.port or 80), self.timeout)
            s = 'CONNECT %s:%s HTTP/1.1\r\nHost: %s\r\n' % (sshost, ssport, sshost)
            if self.pproxyparse.username:
                a = '%s:%s' % (self.pproxyparse.username, self.pproxyparse.password)
                s += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode())
            s += '\r\n'
            self._sock.sendall(s.encode())
            remoterfile = self._sock.makefile('rb', 0)
            data = remoterfile.readline()
            if b'200' not in data:
                raise IOError(0, 'bad response: %s' % data)
            while not data in (b'\r\n', b'\n', b''):
                data = remoterfile.readline()
        else:
            self.logger.error('sssocket does not support parent proxy server: %s for now' % self.parentproxy)
            return 1
        self.setsockopt = self._sock.setsockopt
        self.fileno = self._sock.fileno

    def recv(self, size):
        if not self.connected:
            self.sendall(b'')
        buf = self.__rbuffer
        buf.seek(0, 2)  # seek end
        buf_len = buf.tell()
        self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
        if buf_len < size:
            # Not enough data in buffer?  Try to read.
            data = self.crypto.decrypt(self._sock.recv(max(size - buf_len, self.bufsize)))
            if len(data) == size and not buf_len:
                # Shortcut.  Avoid buffer data copies
                return data
            buf.write(data)
            del data  # explicit free
        buf.seek(0)
        rv = buf.read(size)
        self.__rbuffer.write(buf.read())
        return rv

    def sendall(self, data):
        if self.connected:
            self._sock.sendall(self.crypto.encrypt(data))
        else:
            host, port = self.__address
            self._sock.sendall(self.crypto.encrypt(b''.join([b'\x03',
                                                   chr(len(host)).encode(),
                                                   host.encode(),
                                                   struct.pack(b">H", port),
                                                   data])))
            self.connected = True

    def readline(self, size=-1):
        buf = self.__rbuffer
        buf.seek(0, 2)  # seek end
        if buf.tell() > 0:
            # check if we already have it in our buffer
            buf.seek(0)
            bline = buf.readline(size)
            if bline.endswith('\n') or len(bline) == size:
                self.__rbuffer = StringIO()
                self.__rbuffer.write(buf.read())
                return bline
            del bline
        if size < 0:
            # Read until \n or EOF, whichever comes first
            buf.seek(0, 2)  # seek end
            self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                nl = data.find(b'\n')
                if nl >= 0:
                    nl += 1
                    buf.write(data[:nl])
                    self.__rbuffer.write(data[nl:])
                    break
                buf.write(data)
            del data
            return buf.getvalue()
        else:
            # Read until size bytes or \n or EOF seen, whichever comes first
            buf.seek(0, 2)  # seek end
            buf_len = buf.tell()
            if buf_len >= size:
                buf.seek(0)
                rv = buf.read(size)
                self.__rbuffer = StringIO()
                self.__rbuffer.write(buf.read())
                return rv
            self.__rbuffer = StringIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                left = size - buf_len
                # did we just receive a newline?
                nl = data.find(b'\n', 0, left)
                if nl >= 0:
                    nl += 1
                    # save the excess data to _rbuf
                    self.__rbuffer.write(data[nl:])
                    if buf_len:
                        buf.write(data[:nl])
                        break
                    else:
                        # Shortcut.  Avoid data copy through buf when returning
                        # a substring of our first recv().
                        return data[:nl]
                n = len(data)
                if n == size and not buf_len:
                    # Shortcut.  Avoid data copy through buf when
                    # returning exactly all of our first recv().
                    return data
                if n >= left:
                    buf.write(data[:left])
                    self.__rbuffer.write(data[left:])
                    break
                buf.write(data)
                buf_len += n
                #assert buf_len == buf.tell()
            return buf.getvalue()

    def close(self):
        if self._sock:
            self._sock.close()

    def __del__(self):
        self.close()


class ExpiredError(Exception):
    pass


class autoproxy_rule(object):
    def __init__(self, arg, expire=None, logger=logging):
        super(autoproxy_rule, self).__init__()
        self.rule = arg.strip()
        self.logger = logger
        self.logger.debug('parsing autoproxy rule: %r' % self.rule)
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or '#' in self.rule:
            raise TypeError("invalid autoproxy_rule: %s" % self.rule)
        self.expire = expire
        self._ptrn = self._autopxy_rule_parse(self.rule)

    def _autopxy_rule_parse(self, rule):
        def parse(rule):
            if rule.startswith('||'):
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('/', '').replace('*', '[^/]*').replace('^', r'[^\w%._-]').replace('||', '^(?:https?://)?(?:[^/]+\.)?') + r'(?:[:/]|$)'
                return re.compile(regex)
            elif rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
            elif rule.startswith('|https://'):
                i = rule.find('/', 9)
                regex = rule[9:] if i == -1 else rule[9:i]
                regex = r'^(?:https://)?%s(?:[:/])' % regex.replace('.', r'\.').replace('*', '[^/]*')
                return re.compile(regex)
            else:
                regex = rule.replace('.', r'\.').replace('?', r'\?').replace('*', '.*').replace('^', r'[^\w%._-]')
                regex = re.sub(r'^\|', r'^', regex)
                regex = re.sub(r'\|$', r'$', regex)
                if not rule.startswith(('|', 'http://')):
                    regex = re.sub(r'^', r'^http://.*', regex)
                return re.compile(regex)

        self.override = rule.startswith('@@')
        return parse(rule[2:]) if self.override else parse(rule)

    def match(self, uri):
        if self.expire and self.expire < time.time():
            raise ExpiredError
        return self._ptrn.search(uri)


class parent_proxy(object):
    """docstring for parent_proxy"""
    def __init__(self, conf):
        self.conf = conf
        self.enable_gfwlist = self.conf.userconf.dgetbool('fgfwproxy', 'gfwlist', True)
        self.logger = self.conf.logger
        self.config()

    def config(self):
        self.gfwlist = []
        self.override = []
        self.gfwlist_force = []
        self.temp_rules = set()
        self.redirlst = []
        self.ignore = []

        for line in open('./fgfw-lite/local.txt'):
            self.add_rule(line, force=True)

        for line in open('./fgfw-lite/cloud.txt'):
            self.add_rule(line, force=True)

        if self.enable_gfwlist:
            try:
                with open('./fgfw-lite/gfwlist.txt') as f:
                    data = f.read()
                    if '!' not in data:
                        data = ''.join(data.split())
                        data = base64.b64decode(data).decode()
                    for line in data.splitlines():
                        self.add_rule(line)
            except TypeError:
                self.logger.warning('./fgfw-lite/gfwlist.txt is corrupted!')

        self.geoip = pygeoip.GeoIP('./goagent/GeoIP.dat')

    def add_redirect(self, rule, dest):
        try:
            if rule in [a.rule for a, b in self.redirlst]:
                self.logger.warning('multiple redirector rule! %s' % rule)
                return
            if dest.lower() == 'auto':
                self.ignore.append(autoproxy_rule(rule))
                return
            self.redirlst.append((autoproxy_rule(rule), dest))
        except TypeError as e:
            self.logger.debug('create autoproxy rule failed: %s' % e)

    def add_rule(self, line, force=False):
        rule = line.strip().split()
        if len(rule) == 2:  # |http://www.google.com/url forcehttps
            rule, dest = rule
            self.add_redirect(rule, dest)
        elif len(rule) == 1:
            try:
                o = autoproxy_rule(rule[0])
                if o.override:
                    self.override.append(o)
                elif force:
                    self.gfwlist_force.append(o)
                else:
                    self.gfwlist.append(o)
            except TypeError as e:
                self.logger.debug('create autoproxy rule failed: %s' % e)
        elif rule and not line.startswith(('!', '#')):
            self.logger.warning('Bad autoproxy rule: %r' % line)

    def redirect(self, uri, host=None):
        searchword = re.match(r'^http://([\w-]+)/$', uri)
        if searchword:
            q = searchword.group(1)
            if 'xn--' in q:
                q = q.encode().decode('idna')
            self.logger.debug('Match redirect rule addressbar-search')
            return 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:zh-CN:official' % urlquote(q.encode('utf-8'))
        for rule, result in self.redirlst:
            if rule.match(uri):
                self.logger.debug('Match redirect rule {}, {}'.format(rule.rule, result))
                if rule.override:
                    return None
                if result == 'forcehttps':
                    return uri.replace('http://', 'https://', 1)
                if result.startswith('/') and result.endswith('/'):
                    return rule._ptrn.sub(result[1:-1], uri)
                return result

    @lru_cache(256, timeout=120)
    def ifhost_in_region(self, host, ip):
        try:
            code = self.geoip.country_code_by_addr(ip)
            if code in self.conf.region:
                self.logger.info('%s in %s' % (host, code))
                return True
            return False
        except socket.error:
            return None

    def gfwlist_match(self, uri):
        for i, rule in enumerate(self.gfwlist):
            if rule.match(uri):
                if i > 300:
                    self.gfwlist.insert(0, self.gfwlist.pop(i))
                return True

    def if_gfwlist_force(self, uri, level):
        if level == 4:
            return True
        for rule in self.gfwlist_force:
            try:
                if rule.match(uri):
                    return True
            except ExpiredError:
                self.logger.info('%s expired' % rule.rule)
                self.gfwlist_force.remove(rule)
                self.temp_rules.discard(rule.rule)

    def ifgfwed(self, uri, host, port, ip, level=1):
        if level == 0:
            return False

        if ip is None:
            return True

        if any((ip.is_loopback, ip.is_private)):
            return False

        if any(rule.match(uri) for rule in self.override):
            return False

        if self.if_gfwlist_force(uri, level):
            return True

        if any(rule.match(uri) for rule in self.ignore):
            return None

        if level == 2 and uri.startswith('http://'):
            return True

        if self.conf.HOSTS.get(host) or self.ifhost_in_region(host, str(ip)):
            return None

        if level == 3 or self.gfwlist_match(uri):
            return True

    def parentproxy(self, uri, host, command, level=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443) (no port number is allowed)
            level: 0 -- direct
                   1 -- proxy if force, direct if ip in region or override, proxy if gfwlist
                   2 -- proxy if force or not https, direct if ip in region or override, proxy if gfwlist
                   3 -- proxy if force, direct if ip in region or override, proxy if all
                   4 -- proxy if not local
        '''
        host, port = host

        try:
            ip = get_ip_address(host, port)
        except Exception as e:
            self.logger.warning('resolve %s failed! %s' % (host, repr(e)))
            ip = None

        ifgfwed = self.ifgfwed(uri, host, port, ip, level)

        if ifgfwed is False:
            if ip.is_private:
                return [self.conf.parentlist.dict.get('local') or self.conf.parentlist.dict.get('direct')]
            return [self.conf.parentlist.dict.get('direct')]

        parentlist = copy.copy(self.conf.parentlist.httpsparents if command == 'CONNECT' else self.conf.parentlist.httpparents)
        random.shuffle(parentlist)
        parentlist = sorted(parentlist, key=lambda item: item.httpspriority if command == 'CONNECT' else item.httppriority)

        if self.conf.parentlist.dict.get('local') in parentlist:
            parentlist.remove(self.conf.parentlist.dict.get('local'))

        if ifgfwed or level == 3:
            parentlist.remove(self.conf.parentlist.dict.get('direct'))
            if not parentlist:
                self.logger.warning('No parent proxy available, direct connection is used')
                return [self.conf.parentlist.dict.get('direct')]

        if len(parentlist) > self.conf.maxretry + 1:
            parentlist = parentlist[:self.conf.maxretry + 1]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s' % (command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None'))
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        for fpp in failed_parents:
            self.conf.STATS.log(command, requesthost[0], url, fpp, 0)
        if current_parent:
            self.conf.STATS.log(command, requesthost[0], url, current_parent, success)
        if 'direct' in failed_parents and success:
            if command == 'CONNECT':
                rule = '|https://%s' % requesthost[0]
            else:
                rule = '|http://%s' % requesthost[0] if requesthost[1] == 80 else '%s:%d' % requesthost
            if rule not in self.temp_rules:
                direct_sr = self.conf.STATS.srbhp(requesthost[0], 'direct')
                if direct_sr[1] < 2:
                    exp = 1
                elif direct_sr[0] < 0.1:
                    exp = min(pow(direct_sr[1], 1.5), 60)
                elif direct_sr[0] < 0.5:
                    exp = min(direct_sr[1], 10)
                else:
                    exp = 1
                self.add_temp(rule, exp)

    def add_temp(self, rule, exp=None):
        if rule not in self.temp_rules:
            self.logger.info('add autoproxy rule: %s%s' % (rule, (' expire in %.1f min' % exp) if exp else ''))
            self.gfwlist_force.append(autoproxy_rule(rule, expire=None if not exp else (time.time() + 60 * exp)))
            self.temp_rules.add(rule)
        else:
            return 'already in there'


def updater(conf):
    while 1:
        time.sleep(30)
        conf.HTTPCONN_POOL.purge()
        lastupdate = conf.version.dgetfloat('Update', 'LastUpdate', 0)
        if time.time() - lastupdate > conf.UPDATE_INTV * 60 * 60:
            conf.STATS.purge()
            update(conf, auto=True)
        global CTIMEOUT, ctimer
        if ctimer:
            conf.logger.info('max connection time: %ss in %s' % (max(ctimer), len(ctimer)))
            CTIMEOUT = min(max(3, max(ctimer) * 5), 15)
            conf.logger.info('conn timeout set to: %s' % CTIMEOUT)
            ctimer = []


def update(conf, auto=False):
    if auto and conf.userconf.dgetbool('FGFW_Lite', 'autoupdate') is False:
        return
    filelist = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'), ]
    count = 0
    for url, path in filelist:
        etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
        req = urllib2.Request(url)
        req.add_header('If-None-Match', etag)
        try:
            r = urllib2.urlopen(req)
        except Exception as e:
            conf.logger.info('%s NOT updated. Reason: %r' % (path, e))
        else:
            data = r.read()
            if r.getcode() == 200 and data:
                with open(path, 'wb') as localfile:
                    localfile.write(data)
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), r.info().getheader('ETag'))
                conf.confsave()
                conf.logger.info('%s Updated.' % path)
            else:
                conf.logger.info('{} NOT updated. Reason: {}'.format(path, str(r.getcode())))
    branch = conf.userconf.dget('FGFW_Lite', 'branch', 'master')
    try:
        r = json.loads(urllib2.urlopen('https://github.com/v3aqb/fwlite/raw/%s/fgfw-lite/update.json' % branch).read())
    except Exception as e:
        conf.logger.info('read update.json failed. Reason: %r' % e)
    else:
        import hashlib
        for path, v, in r.items():
            try:
                if v == conf.version.dget('Update', path.replace('./', '').replace('/', '-'), ''):
                    conf.logger.debug('{} Not Modified'.format(path))
                    continue
                fdata = urllib2.urlopen('https://github.com/v3aqb/fwlite/raw/%s%s' % (branch, path[1:])).read()
                h = hashlib.new("sha256", fdata).hexdigest()
                if h != v:
                    conf.logger.warning('{} NOT updated. hash mismatch.'.format(path))
                    continue
                if not os.path.isdir(os.path.dirname(path)):
                    os.mkdir(os.path.dirname(path))
                with open(path, 'wb') as localfile:
                    localfile.write(fdata)
                conf.logger.info('%s Updated.' % path)
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), h)
                if not path.endswith(('txt', 'ini')):
                    count += 1
            except Exception as e:
                conf.logger.error('update failed! %r\n%s' % (e, traceback.format_exc()))
        conf.version.set('Update', 'LastUpdate', str(time.time()))
    conf.confsave()
    restart(conf)
    if count:
        conf.logger.info('Update Completed, %d file Updated.' % count)


def restart(conf):
    conf.confsave()
    for item in FGFWProxyHandler.ITEMS:
        item.restart()
    conf.PARENT_PROXY.config()


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


class goagentHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def config(self):
        self.cwd = '%s/goagent' % WORKINGDIR
        self.cmd = '{} {}/goagent/proxy.py'.format(PYTHON2, WORKINGDIR)
        self.enable = self.conf.userconf.dgetbool('goagent', 'enable', True)
        with open('%s/goagent/proxy.py' % WORKINGDIR, 'rb') as f:
            t = f.read()
        with open('%s/goagent/proxy.py' % WORKINGDIR, 'wb') as f:
            t = t.replace(b"ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)", b'pass')
            f.write(t)
        if self.enable:
            self._config()

    def _config(self):
        goagent = SConfigParser()
        goagent.read('./goagent/proxy.sample.ini')

        if self.conf.userconf.dget('goagent', 'gaeappid', 'goagent') != 'goagent':
            goagent.set('gae', 'appid', self.conf.userconf.dget('goagent', 'gaeappid', 'goagent'))
            goagent.set("gae", "password", self.conf.userconf.dget('goagent', 'gaepassword', ''))
        else:
            self.logger.warning('GoAgent APPID is NOT set! Fake APPID is used.')
            goagent.set('gae', 'appid', 'dummy')
        goagent.set('gae', 'mode', self.conf.userconf.dget('goagent', 'mode', 'https'))
        goagent.set('gae', 'profile', self.conf.userconf.dget('goagent', 'profile', 'ipv4'))
        goagent.set('gae', 'keepalive', self.conf.userconf.dget('goagent', 'keepalive', '0'))
        goagent.set('gae', 'obfuscate', self.conf.userconf.dget('goagent', 'obfuscate', '0'))
        goagent.set('gae', 'validate', self.conf.userconf.dget('goagent', 'validate', '0'))
        goagent.set('gae', 'pagespeed', self.conf.userconf.dget('goagent', 'pagespeed', '0'))
        goagent.set('gae', 'options', self.conf.userconf.dget('goagent', 'options', ''))
        goagent.set('gae', 'sslversion', self.conf.userconf.dget('goagent', 'options', 'TLSv1'))
        if self.conf.userconf.dget('goagent', 'google_cn', ''):
            goagent.set('iplist', 'google_cn', self.conf.userconf.dget('goagent', 'google_cn', ''))
        if self.conf.userconf.dget('goagent', 'google_hk', ''):
            goagent.set('iplist', 'google_hk', self.conf.userconf.dget('goagent', 'google_hk', ''))
        self.conf.addparentproxy('goagent', 'http://127.0.0.1:8087 20 200')

        if self.conf.userconf.dget('goagent', 'phpfetchserver'):
            goagent.set('php', 'enable', '1')
            goagent.set('php', 'password', self.conf.userconf.dget('goagent', 'phppassword', '123456'))
            goagent.set('php', 'fetchserver', self.conf.userconf.dget('goagent', 'phpfetchserver', 'http://.com/'))
            self.conf.addparentproxy('goagent-php', 'http://127.0.0.1:8088')
        else:
            goagent.set('php', 'enable', '0')

        goagent.set('pac', 'enable', '0')

        goagent.set('proxy', 'autodetect', '0')
        if self.conf.parentlist.dict.get('direct') and self.conf.parentlist.dict.get('direct').parse.scheme == 'http':
            p = self.conf.parentlist.dict.get('direct').parse
            goagent.set('proxy', 'enable', '1')
            goagent.set('proxy', 'host', p.hostname)
            goagent.set('proxy', 'port', p.port)
            goagent.set('proxy', 'username', p.username or '')
            goagent.set('proxy', 'password', p.password or '')
        if '-hide' in sys.argv[1:]:
            goagent.set('listen', 'visible', '0')
        else:
            goagent.set('listen', 'visible', '1')

        with open('./goagent/proxy.ini', 'w') as configfile:
            goagent.write(configfile)


class ParentProxy(object):
    def __init__(self, name, proxy):
        proxy, _, priority = proxy.partition(' ')
        httppriority, _, httpspriority = priority.partition(' ')
        httppriority = httppriority or 99
        httpspriority = httpspriority or httppriority
        if proxy == 'direct':
            proxy = ''
        self.name = name
        self.proxy = proxy
        self.parse = urlparse.urlparse(self.proxy)
        self.httppriority = int(httppriority)
        self.httpspriority = int(httpspriority)
        if self.parse.scheme.lower() == 'sni':
            self.httppriority = -1

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<ParentProxy: %s %s %s>' % (self.name or 'direct', self.httppriority, self.httpspriority)


class ParentProxyList(object):
    def __init__(self):
        self.httpparents = []
        self.httpsparents = []
        self.dict = {}

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        if parentproxy.httppriority >= 0:
            self.httpparents.append(parentproxy)
        if parentproxy.httpspriority >= 0:
            self.httpsparents.append(parentproxy)
        self.dict[parentproxy.name] = parentproxy

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy))


class Config(object):
    def __init__(self, logger=logging):
        self.logger = logger
        self.STATS = stats()
        self.HTTPCONN_POOL = httpconn_pool(self.logger)
        self.version = SConfigParser()
        self.userconf = SConfigParser()
        self.reload()
        self.UPDATE_INTV = 6
        self.parentlist = ParentProxyList()
        self.HOSTS = defaultdict(list)
        listen = self.userconf.dget('fgfwproxy', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        self.region = set(x.upper() for x in self.userconf.dget('fgfwproxy', 'region', 'cn').split('|') if x.strip())

        self.xheaders = self.userconf.dgetbool('fgfwproxy', 'xheaders', False)

        self.addparentproxy('direct', 'direct 0')
        if self.userconf.dget('fgfwproxy', 'parentproxy', ''):
            self.addparentproxy('direct', '%s 0' % self.userconf.dget('fgfwproxy', 'parentproxy', ''))
            self.addparentproxy('local', 'direct 100')

        for k, v in self.userconf.items('parents'):
            self.addparentproxy(k, v)

        self.maxretry = self.userconf.dgetint('fgfwproxy', 'maxretry', 4)

        self.goagent = goagentHandler(self)

        for host, ip in self.userconf.items('hosts'):
            if ip not in self.HOSTS.get(host, []):
                self.HOSTS[host].append(ip)

        if os.path.isfile('./fgfw-lite/hosts'):
            for line in open('./fgfw-lite/hosts'):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ip, host = line.split()
                        if ip not in self.HOSTS.get(host, []):
                            self.HOSTS[host].append(ip)
                    except Exception as e:
                        self.logger.warning('%s %s' % (e, line))

        self.PARENT_PROXY = parent_proxy(self)

    def reload(self):
        self.version.read('version.ini')
        self.userconf.read('userconf.ini')

    def confsave(self):
        with open('version.ini', 'w') as f:
            self.version.write(f)
        self.userconf.read('userconf.ini')

    def addparentproxy(self, name, proxy):
        self.parentlist.addstr(name, proxy)
        self.logger.info('adding parent proxy: %s: %s' % (name, proxy))


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()


def main():
    if sys.platform.startswith('win'):
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(u'FGFW-Lite v%s' % __version__)
    conf = Config()
    updatedaemon = Thread(target=updater, args=([conf]))
    updatedaemon.daemon = True
    updatedaemon.start()
    for i, level in enumerate(list(conf.userconf.dget('fgfwproxy', 'profile', '134'))):
        server = ThreadingHTTPServer((conf.listen[0], conf.listen[1] + i), ProxyHandler, conf=conf, level=int(level))
        t = Thread(target=server.serve_forever)
        t.start()
    t.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
