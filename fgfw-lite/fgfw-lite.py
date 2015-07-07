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

__version__ = '4.8'

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
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    sys.stderr.write('Warning: gevent not found! Using thread instead...\n')
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('Warning: Please update gevent to the latest 1.0 version!\n')
from collections import defaultdict, deque
import subprocess
import shlex
import time
import re
import io
import datetime
import errno
import atexit
import base64
import itertools
import json
import ftplib
import random
import select
import shutil
import socket
import sqlite3
import traceback
try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import BytesIO as StringIO
from threading import Thread, RLock, Timer
from repoze.lru import lru_cache
import logging
import logging.handlers

logging.basicConfig(level=logging.INFO,
                    format='FW-Lite %(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S', filemode='a+')
from util import parse_hostport, is_connection_dropped, SConfigParser, sizeof_fmt, ip_to_country_code
from apfilter import ap_rule, ap_filter, ExpiredError
from parent_proxy import ParentProxyList, ParentProxy
from connection import create_connection
import resolver
from resolver import get_ip_address
from redirector import redirector
from httputil import read_reaponse_line, read_headers, read_header_data
try:
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from ipaddress import ip_address, IPv4Address
except ImportError:
    import urllib2
    import urlparse
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPv4Address

if sys.platform.startswith('win'):
    PYTHON2 = '"%s/Python27/python27.exe"' % WORKINGDIR
else:
    for cmd in ('python2.7', 'python27', 'python2'):
        if subprocess.call(shlex.split('which %s' % cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            PYTHON2 = cmd
            break

NetWorkIOError = (IOError, OSError)
DEFAULT_TIMEOUT = 5
FAKEGIF = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;'


def prestart():
    s = 'FW_Lite ' + __version__
    if gevent:
        s += ' with gevent %s' % gevent.__version__
    logging.info(s)

    if not os.path.isfile('./userconf.ini'):
        shutil.copyfile('./userconf.sample.ini', './userconf.ini')

    if not os.path.isfile('./fgfw-lite/local.txt'):
        with open('./fgfw-lite/local.txt', 'w') as f:
            f.write('''\
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

prestart()


class stats(object):
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("create table log (ts real, date text, command text, hostname text, url text, ppname text, success integer)")
    logger = logging.getLogger('FW_Lite')

    def __init__(self, conf):
        self.conf = conf
        Timer(3600, self._purge, ()).start()

    def log(self, command, hostname, url, ppname, success):
        with self.con:
            self.con.execute('INSERT into log values (?,?,?,?,?,?,?)', (time.time(), datetime.date.today(), command, hostname, url, ppname, success))
        if not success:
            if self.is_bad_pp('direct') is False:  # if internet connection is good
                if self.is_bad_pp(ppname):
                    self.logger.info('Probable bad parent: %s, remove.' % ppname)
                    self.conf.parentlist.report_bad(ppname)

    def srbh(self, hostname, sincetime=None):
        '''success rate by hostname'''
        if sincetime is None:
            sincetime = time.time() - 10 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where hostname = (?) and ts >= (?)', (hostname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbp(self, ppname, sincetime=None):
        '''success rate by ppname'''
        if sincetime is None:
            sincetime = time.time() - 10 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where ppname = (?) and ts >= (?)', (ppname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbhp(self, hostname, ppname, sincetime=None):
        '''success rate by hostname and ppname'''
        if sincetime is None:
            sincetime = time.time() - 30 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where hostname = (?) and ppname = (?) and ts >= (?)', (hostname, ppname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbhwp(self, hostname, sincetime=None):
        '''success rate by hostname with a parentproxy'''
        if sincetime is None:
            sincetime = time.time() - 30 * 60
        r = next(self.con.execute("SELECT count(*), sum(success) from log where hostname = (?) and ppname <> 'direct' and ts >= (?)", (hostname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def is_bad_pp(self, ppname):
        '''if a given ppname is unavailable'''
        sincetime = time.time() - 10 * 60
        result = self.con.execute('SELECT success from log where ppname = (?) and ts >= (?) order by ts desc LIMIT 5', (ppname, sincetime))
        rsum = count = 0
        for s in result:
            rsum += s[0]
            count += 1
        self.logger.debug('%s %s %s %r' % (ppname, count, rsum, not rsum if count >= 5 else None))
        if count >= 5:
            return not rsum
        return None

    def _purge(self, befortime=None):
        if not befortime:
            befortime = time.time() - 24 * 60 * 60
        with self.con:
            self.con.execute('DELETE from log where ts < (?)', (befortime, ))
        Timer(3600, self._purge, ()).start()


class httpconn_pool(object):
    def __init__(self):
        self.POOL = defaultdict(deque)  # {upstream_name: [(soc, ppname), ...]}
        self.socs = {}  # keep track of sock info
        self.timerwheel = defaultdict(set)  # a list of socket object
        self.timerwheel_iter = itertools.cycle(range(10))
        self.timerwheel_index = next(self.timerwheel_iter)
        self.lock = RLock()
        self.logger = logging.getLogger('FW_Lite')
        Timer(30, self._purge, ()).start()

    def put(self, upstream_name, soc, ppname):
        with self.lock:
            self.POOL[upstream_name].append((soc, ppname))
            self.socs[soc] = (self.timerwheel_index, ppname, upstream_name)
            self.timerwheel[self.timerwheel_index].add(soc)

    def get(self, upstream_name):
        lst = self.POOL.get(upstream_name)
        with self.lock:
            while lst:
                sock, pproxy = lst.popleft()
                if is_connection_dropped([sock]):
                    sock.close()
                    self._remove(sock)
                    continue
                self._remove(sock)
                return (sock, pproxy)

    def _remove(self, soc):
        twindex, ppn, upsname = self.socs.pop(soc)
        self.timerwheel[twindex].discard(soc)
        if (soc, ppn) in self.POOL[upsname]:
            self.POOL[upsname].remove((soc, ppn))

    def _purge(self):
        pcount = 0
        with self.lock:
            for soc in is_connection_dropped(self.socs.keys()):
                soc.close()
                self._remove(soc)
                pcount += 1
            self.timerwheel_index = next(self.timerwheel_iter)
            for soc in list(self.timerwheel[self.timerwheel_index]):
                soc.close()
                self._remove(soc)
                pcount += 1
        if pcount:
            self.logger.debug('%d remotesoc purged, %d in connection pool.(%s)' % (pcount, len(self.socs), ', '.join([k[0] if isinstance(k, tuple) else k for k, v in self.POOL.items() if v])))
        Timer(30, self._purge, ()).start()


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

    def _request_is_loopback(self, req):
        try:
            return get_ip_address(req[0]).is_loopback
        except Exception:
            pass

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
    bufsize = 32 * 1024
    timeout = 60

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
        if self.path:
            self.logger.debug(self.shortpath or self.path + ' finished.')
            self.logger.debug('upload: %d, download %d' % tuple(self.traffic_count))
        if self.remotesoc:
            self.remotesoc.close()

    def getparent(self):
        if self._proxylist is None:
            # goagent does not support big POST
            nogoagent = True if self.headers.get("Transfer-Encoding") or int(self.headers.get('Content-Length', 0)) > 1024 * 1024 else False
            self._proxylist = self.conf.PARENT_PROXY.parentproxy(self.path, self.requesthost, self.command, self.server.proxy_level, nogoagent)
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

        if self._request_is_loopback(self.requesthost) or self.ssclient:
            if ip_address(self.client_address[0]).is_loopback:
                if self.requesthost[1] in range(self.conf.listen[1], self.conf.listen[1] + self.conf.profiles):
                    return self.api(parse)
            else:
                return self.send_error(403, 'Go fuck yourself!')

        if str(get_ip_address(self.requesthost[0])) == self.connection.getsockname()[0]:
            if self.requesthost[1] in range(self.conf.listen[1], self.conf.listen[1] + len(self.conf.userconf.dget('fgfwproxy', 'profile', '134'))):
                if self.conf.userconf.dgetbool('fgfwproxy', 'remoteapi', False):
                    return self.api(parse)
                return self.send_error(403)

        if not self.ssclient and self.conf.xheaders:
            ipl = [ip.strip() for ip in self.headers.get('X-Forwarded-For', '').split(',') if ip.strip()]
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
                client_close = conntype.lower() == 'close'
            else:
                client_close = conntype.lower() != 'keep_alive'
            del self.headers['Upgrade']
            del self.headers['Proxy-Connection']
            self.headers['Connection'] = 'keep_alive'
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
                self.phase = 'reading response_line'
                response_line, protocol_version, response_status, response_reason = read_reaponse_line(remoterfile)
            # read response headers
            while response_status == 100:
                hdata = read_header_data(remoterfile)
                self._wfile_write(response_line + hdata)
                response_line, protocol_version, response_status, response_reason = read_reaponse_line(remoterfile)
            self.phase = 'reading response header'
            header_data, response_header = read_headers(remoterfile)
            conntype = response_header.get('Connection', "")
            if protocol_version >= b"HTTP/1.1":
                remote_close = conntype.lower() == 'close'
            else:
                remote_close = conntype.lower() != 'keep_alive'
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
                if line.startswith('Connection'):
                    header_data += b'Connection: close\r\n' if client_close else b'Connection: keep_alive\r\n'
                else:
                    header_data += line
            self.wfile_write(response_line)
            self.wfile_write(header_data)
            # verify
            if response_status > 500 and self.ppname.startswith('goagent'):
                raise IOError(0, 'bad response status code from goagent: %d' % response_status)
            if response_status in (301, 302) and self.conf.PARENT_PROXY.bad302(response_header.get('Location')):
                raise IOError(0, 'Bad 302!')
            # read response body
            self.phase = 'reading response body'
            if self.command == 'HEAD' or 100 <= response_status < 200 or response_status in (204, 205, 304):
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
            self.phase = 'request finish'
            self.conf.PARENT_PROXY.notify(self.command, self.shortpath, self.requesthost, True if response_status < 400 else False, self.failed_parents, self.ppname)
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

        if self._request_is_loopback(self.requesthost) or self.ssclient:
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
            count += 1
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
                    if self.retryable:
                        self.rbuffer.append(data)
                    elif count > 1:
                        self.phase = 'client key exchange sent'
                        break
                if self.remotesoc in ins:
                    self.phase = 'read from remote'
                    data = self.remotesoc.recv(self.bufsize)
                    if not data:  # remote connection closed
                        reason = 'remote closed'
                        break
                    self._wfile_write(data)
            except NetWorkIOError as e:
                self.logger.warning('do_CONNECT error: %r on %s %s' % (e, self.phase, count))
                break
        if self.rbuffer and self.rbuffer[0].startswith((b'\x16\x03\x00', b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03')) and count < 2:
            self.logger.warning('TLS key exchange failed? hostname: %s, %s %s' % (self.requesthost[0], self.phase, count))
        if self.retryable:
            reason = reason or "don't know why"
            if reason == 'client closed':
                return
            self.logger.warning('%s %s via %s failed on %s! %s' % (self.command, self.path, self.ppname, self.phase, reason))
            return self._do_CONNECT(True)
        self.rbuffer = deque()
        self.conf.PARENT_PROXY.notify(self.command, self.path, self.requesthost, True, self.failed_parents, self.ppname)
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
                self.rtimeout = min(2 ** len(self.failed_parents) + self.conf.timeout, 10)
                self.ctimeout = min(2 ** len(self.failed_parents) + self.conf.timeout, 10)
        else:
            self.ctimeout = self.rtimeout = 10

    def _http_connect_via_proxy(self, netloc, iplist):
        if not self.failed_parents:
            res = self.HTTPCONN_POOL.get(self.upstream_name)
            if res:
                self._proxylist.insert(0, self.conf.parentlist.get(self.ppname))
                sock, self.ppname = res
                self.on_conn_log()
                return sock
        return self._connect_via_proxy(netloc, iplist)

    def _connect_via_proxy(self, netloc, iplist=None, tunnel=False):
        self.on_conn_log()
        return create_connection(netloc, ctimeout=self.ctimeout, iplist=iplist, parentproxy=self.pproxy, via=self.conf.parentlist.get('direct'), tunnel=tunnel)

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
            data = json.dumps([(index, rule.rule, rule.expire) for index, rule in enumerate(self.conf.PARENT_PROXY.temp)])
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/localrule' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, int exp)'
            rule, exp = json.loads(body)
            result = self.conf.PARENT_PROXY.add_temp(rule, exp)
            self.write(400 if result else 201, result, 'application/json')
            return self.conf.stdout()
        elif parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                if rule:
                    assert base64.urlsafe_b64decode(rule) == self.conf.PARENT_PROXY.temp[int(parse.path[15:])].rule
                result = self.conf.PARENT_PROXY.temp.pop(int(parse.path[15:]))
                self.conf.PARENT_PROXY.temp_rules.discard(result.rule)
                self.write(200, json.dumps([int(parse.path[15:]), result.rule, result.expire]), 'application/json')
                return self.conf.stdout()
            except Exception as e:
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
        elif parse.path == '/api/goagent/pid' and self.command == 'GET':
            data = json.dumps(self.conf.goagent.pid)
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/goagent/setting' and self.command == 'GET':
            data = json.dumps(self.conf.goagent.setting())
            return self.write(200, data, 'application/json')
        elif parse.path == '/api/goagent/setting' and self.command == 'POST':
            self.conf.goagent.setting(json.loads(body))
            return self.write(200, data, 'application/json')
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

ASIA = ('AE', 'AF', 'AL', 'AZ', 'BD', 'BH', 'BN', 'BT', 'CN', 'CY', 'HK', 'ID',
        'IL', 'IN', 'IQ', 'IR', 'JO', 'JP', 'KH', 'KP', 'KR', 'KW', 'KZ', 'LA',
        'LB', 'LU', 'MN', 'MO', 'MV', 'MY', 'NP', 'OM', 'PH', 'PK', 'QA', 'SA',
        'SG', 'SY', 'TH', 'TJ', 'TM', 'TW', 'UZ', 'VN', 'YE')
AFRICA = ('AO', 'BI', 'BJ', 'BW', 'CF', 'CG', 'CM', 'CV', 'DZ', 'EG', 'ET', 'GA', 'GH',
          'GM', 'GN', 'GQ', 'KE', 'LY', 'MA', 'MG', 'ML', 'MR', 'MU', 'MZ', 'NA', 'NE',
          'NG', 'RW', 'SD', 'SN', 'SO', 'TN', 'TZ', 'UG', 'ZA', 'ZM', 'ZR', 'ZW')
NA = ('BM', 'BS', 'CA', 'CR', 'CU', 'GD', 'GT', 'HN', 'HT', 'JM', 'MX', 'NI', 'PA', 'US', 'VE')
SA = ('AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'GY', 'PE', 'PY', 'UY')
EU = ('AT', 'BE', 'BG', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GB',
      'GR', 'HR', 'HU', 'IE', 'IS', 'IT', 'LT', 'LV', 'MC', 'MD', 'MT', 'NL',
      'NO', 'PL', 'PT', 'RO', 'RU', 'SE', 'SK', 'SM', 'UA', 'UK', 'VA', 'YU')
PACIFIC = ('AU', 'CK', 'FJ', 'GU', 'NZ', 'PG', 'TO')

continent_list = [ASIA, AFRICA, NA, SA, EU, PACIFIC]


class parent_proxy(object):
    """docstring for parent_proxy"""
    def __init__(self, conf):
        self.conf = conf
        self.logger = self.conf.logger
        self.config()
        self.STATS = stats(self.conf)

    def config(self):
        self.gfwlist = ap_filter()
        self.force = ap_filter()
        self.temp = []
        self.temp_rules = set()
        self.ignore = []

        for line in open('./fgfw-lite/local.txt'):
            rule, _, dest = line.strip().partition(' ')
            if dest:  # |http://www.google.com/url forcehttps
                self.add_redirect(rule, dest)
            else:
                self.add_temp(line, quiet=True)

        if self.conf.rproxy is False:
            for line in open('./fgfw-lite/cloud.txt'):
                rule, _, dest = line.strip().partition(' ')
                if dest:  # |http://www.google.com/url forcehttps
                    self.add_redirect(rule, dest)
                else:
                    self.add_rule(line, force=True)

            self.logger.info('loading  gfwlist...')
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

    def redirect(self, hdlr):
        return self.conf.REDIRECTOR.redirect(hdlr)

    def add_redirect(self, rule, dest):
        return self.conf.REDIRECTOR.add_redirect(rule, dest, self)

    def bad302(self, uri):
        return self.conf.REDIRECTOR.bad302(uri)

    def add_ignore(self, rule):
        self.ignore.append(ap_rule(rule))

    def add_rule(self, line, force=False):
        try:
            if '||' in line:
                self.force.add(line)
            elif force:
                self.force.add(line)
            else:
                self.gfwlist.add(line)
        except ValueError as e:
            self.logger.debug('create autoproxy rule failed: %s' % e)

    @lru_cache(256, timeout=120)
    def ifhost_in_region(self, host, ip):
        try:
            code = ip_to_country_code(ip)
            if code in self.conf.region:
                self.logger.info('%s in %s' % (host, code))
                return True
            return False
        except:
            pass

    def if_temp(self, uri):
        for rule in self.temp:
            try:
                if rule.match(uri):
                    return not rule.override
            except ExpiredError:
                self.logger.info('%s expired' % rule.rule)
                self.conf.stdout()
                self.temp.remove(rule)
                self.temp_rules.discard(rule.rule)

    def ifgfwed(self, uri, host, port, ip, level=1):
        if level == 0:
            return False

        if self.conf.rproxy:
            return None

        if ip is None:
            return True

        if any((ip.is_loopback, ip.is_private)):
            return False

        if level == 4:
            return True

        a = self.if_temp(uri)
        if a is not None:
            return a

        a = self.force.match(uri, host)
        if a is not None:
            return a

        if any(rule.match(uri) for rule in self.ignore):
            return None

        if level == 2 and uri.startswith('http://'):
            return True

        if self.conf.HOSTS.get(host) or self.ifhost_in_region(host, str(ip)):
            return None

        if level == 3:
            return True

        if self.conf.userconf.dgetbool('fgfwproxy', 'gfwlist', True) and self.gfwlist.match(uri):
            return True

    def parentproxy(self, uri, host, command, level=1, nogoagent=False):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443) (no port number is allowed)
            level: 0 -- direct
                   1 -- auto:        proxy if force, direct if ip in region or override, proxy if gfwlist
                   2 -- encrypt all: proxy if force or not https, direct if ip in region or override, proxy if gfwlist
                   3 -- chnroute:    proxy if force, direct if ip in region or override, proxy if all
                   4 -- global:      proxy if not local
        '''
        host, port = host

        ip = get_ip_address(host)

        ifgfwed = self.ifgfwed(uri, host, port, ip, level)

        if ifgfwed is False:
            if ip.is_private:
                return [self.conf.parentlist.local or self.conf.parentlist.direct]
            return [self.conf.parentlist.direct]

        parentlist = list(self.conf.parentlist.httpsparents() if command == 'CONNECT' else self.conf.parentlist.httpparents())
        if len(parentlist) < self.conf.maxretry:
            parentlist.extend(parentlist[1:] if not ifgfwed else parentlist)
            parentlist = parentlist[:self.conf.maxretry]

        def key(parent):
            priority = parent.httpspriority if command == 'CONNECT' else parent.httppriority
            if not ip:
                return priority
            result = priority
            if parent.country_code is None:
                parent.get_location()
            if parent.country_code is None:
                result = priority + 5
            parent_cc = parent.country_code
            dest = ''
            dest = ip_to_country_code(ip)
            if parent_cc == dest:
                result = priority - 5
            else:
                for continent in continent_list:
                    if parent_cc in continent and dest in continent:
                        result = priority - 3
                        break
            return result

        if len(parentlist) > 1:
            random.shuffle(parentlist)
            parentlist = sorted(parentlist, key=key)

        if nogoagent and self.conf.parentlist.get('goagent') in parentlist:
            parentlist.remove(self.conf.parentlist.get('goagent'))

        if ifgfwed:
            if not parentlist:
                self.logger.warning('No parent proxy available, direct connection is used')
                return [self.conf.parentlist.get('direct')]
        else:
            parentlist.insert(0, self.conf.parentlist.direct)

        if len(parentlist) == 1 and parentlist[0] is self.conf.parentlist.get('direct'):
            return parentlist

        if len(parentlist) > self.conf.maxretry:
            parentlist = parentlist[:self.conf.maxretry]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s' % (command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None'))
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if success:
            for fpp in failed_parents:
                self.STATS.log(command, requesthost[0], url, fpp, 0)
            if current_parent:
                self.STATS.log(command, requesthost[0], url, current_parent, success)
            if 'direct' in failed_parents:
                if command == 'CONNECT':
                    rule = '|https://%s' % requesthost[0]
                else:
                    rule = '|http://%s' % requesthost[0] if requesthost[1] == 80 else '%s:%d' % requesthost
                if rule not in self.temp_rules:
                    direct_sr = self.STATS.srbhp(requesthost[0], 'direct')
                    if direct_sr[1] < 2:
                        exp = 1
                    elif direct_sr[0] < 0.1:
                        exp = min(pow(direct_sr[1], 1.5), 60)
                    elif direct_sr[0] < 0.5:
                        exp = min(direct_sr[1], 10)
                    else:
                        exp = 1
                    self.add_temp(rule, exp)
                    self.conf.stdout()

    def add_temp(self, rule, exp=None, quiet=False):
        rule = rule.strip()
        if rule not in self.temp_rules:
            try:
                if not quiet:
                    self.logger.info('add autoproxy rule: %s%s' % (rule, (' expire in %.1f min' % exp) if exp else ''))
                self.temp.append(ap_rule(rule, expire=None if not exp else (time.time() + 60 * exp)))
                self.temp_rules.add(rule)
            except ValueError:
                pass
        else:
            return 'already in there'


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
    filelist = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'), ]
    for url, path in filelist:
        etag = conf.version.dget('Update', path.replace('./', '').replace('/', '-'), '')
        req = urllib2.Request(url)
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
                conf.version.set('Update', path.replace('./', '').replace('/', '-'), r.info().getheader('ETag'))
                conf.confsave()
                conf.logger.info('%s Updated.' % path)
            else:
                conf.logger.info('{} NOT updated: {}'.format(path, str(r.getcode())))
    branch = conf.userconf.dget('FGFW_Lite', 'branch', 'master')
    count = 0
    try:
        s = urllib2.urlopen('http://fwlite.tk/ver').read()
        if int(s) < conf.version.dgetint('Update', 'ver', 0):
            conf.logger.info('server version invalid, abort.')
            return
        else:
            conf.version.set('Update', 'ver', s)
    except Exception as e:
        conf.logger.info('read server ver failed: %r' % e)
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
                conf.logger.info('Update: Downloading %s' % path)
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


class goagentHandler(FGFWProxyHandler):
    """docstring for ClassName"""
    def config(self):
        self.cwd = '%s/goagent' % WORKINGDIR
        self.cmd = '%s %s/goagent/proxy.py' % (PYTHON2, WORKINGDIR.replace(' ', '\ '))
        self.enable = self.conf.userconf.dgetbool('goagent', 'enable', False)

        self._config()

    def _config(self):
        self.conf.parentlist.remove('goagent')
        self.conf.parentlist.remove('goagent-php')
        goagent = SConfigParser()
        goagent.read('./goagent/proxy.sample.ini')

        goagent.set('gae', 'appid', self.conf.userconf.dget('goagent', 'gaeappid', 'goagent'))
        if self.enable and self.conf.userconf.dget('goagent', 'gaeappid', 'goagent') == 'goagent':
            self.logger.warning('GoAgent APPID is NOT set!')
            self.enable = False
        goagent.set("gae", "password", self.conf.userconf.dget('goagent', 'gaepassword', ''))
        goagent.set('gae', 'mode', self.conf.userconf.dget('goagent', 'mode', 'https'))
        goagent.set('gae', 'ipv6', self.conf.userconf.dget('goagent', 'ipv6', '0'))
        goagent.set('gae', 'sslversion', self.conf.userconf.dget('goagent', 'options', 'TLSv1'))
        goagent.set('gae', 'keepalive', self.conf.userconf.dget('goagent', 'keepalive', '0'))
        goagent.set('gae', 'obfuscate', self.conf.userconf.dget('goagent', 'obfuscate', '0'))
        goagent.set('gae', 'pagespeed', self.conf.userconf.dget('goagent', 'pagespeed', '0'))
        goagent.set('gae', 'validate', self.conf.userconf.dget('goagent', 'validate', '1'))
        goagent.set('gae', 'options', self.conf.userconf.dget('goagent', 'options', ''))

        if self.conf.userconf.dget('goagent', 'google_cn', ''):
            goagent.set('iplist', 'google_cn', self.conf.userconf.dget('goagent', 'google_cn', ''))
        if self.conf.userconf.dget('goagent', 'google_hk', ''):
            goagent.set('iplist', 'google_hk', self.conf.userconf.dget('goagent', 'google_hk', ''))
        if self.enable:
            self.conf.addparentproxy('goagent', 'http://127.0.0.1:8087 20 200 8')
            self.conf.parentlist.get('goagent').country_code = 'US'

        if self.conf.userconf.dget('goagent', 'vps'):
            goagent.set('vps', 'enable', '1')
            goagent.set('vps', 'fetchserver', self.conf.userconf.dget('goagent', 'vps'))
            self.conf.addparentproxy('goagent-vps', 'http://127.0.0.1:8088')
        else:
            goagent.set('php', 'enable', '0')

        goagent.set('pac', 'enable', '0')

        goagent.set('proxy', 'autodetect', '0')
        if self.conf.parentlist.get('direct') and self.conf.parentlist.get('direct').scheme == 'http':
            p = self.conf.parentlist.get('direct').parse
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

    def setting(self, conf=None):
        if not conf:
            return (self.conf.userconf.dgetbool('goagent', 'enable', True), self.conf.userconf.dget('goagent', 'gaeappid', 'goagent'), self.conf.userconf.dget('goagent', 'gaepassword', ''))
        else:
            self.enable, appid, passwd = conf
            self.conf.userconf.set('goagent', 'enable', '1' if self.enable else '0')
            self.conf.userconf.set('goagent', 'gaeappid', appid)
            self.conf.userconf.set('goagent', 'gaepassword', passwd)
            self.conf.confsave()
            self.restart()
            self.conf.stdout()


class Config(object):
    def __init__(self):
        self.logger = logging.getLogger('FW_Lite')
        self.version = SConfigParser()
        self.userconf = SConfigParser()
        self.reload()
        self.UPDATE_INTV = 6
        self.timeout = self.userconf.dgetint('fgfwproxy', 'timeout', 4)
        ParentProxy.DEFAULT_TIMEOUT = self.timeout
        self.parentlist = ParentProxyList()
        self.HOSTS = defaultdict(list)
        self.GUI = '-GUI' in sys.argv
        self.rproxy = self.userconf.dgetbool('fgfwproxy', 'rproxy', False)

        listen = self.userconf.dget('fgfwproxy', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        self.local_ip = set(socket.gethostbyname_ex(socket.gethostname())[2])

        self.PAC = '''\
function FindProxyForURL(url, host) {
if (isPlainHostName(host) ||
    host.indexOf('127.') == 0 ||
    host.indexOf('192.168.') == 0 ||
    host.indexOf('10.') == 0 ||
    shExpMatch(host, 'localhost.*'))
    {
        return 'DIRECT';
    }
return "PROXY %s:%s; DIRECT";}''' % (socket.gethostbyname(socket.gethostname()), self.listen[1])
        if self.userconf.dget('fgfwproxy', 'pac', ''):
            if os.path.isfile(self.userconf.dget('fgfwproxy', 'pac', '')):
                self.PAC = open(self.userconf.dget('fgfwproxy', 'pac', '')).read()
            else:
                self.PAC = '''\
function FindProxyForURL(url, host) {
if (isPlainHostName(host) ||
    host.indexOf('127.') == 0 ||
    host.indexOf('192.168.') == 0 ||
    host.indexOf('10.') == 0 ||
    shExpMatch(host, 'localhost.*'))
    {
        return 'DIRECT';
    }
return "PROXY %s; DIRECT";}''' % self.userconf.dget('fgfwproxy', 'pac', '')
        self.PAC = self.PAC.encode()

        if self.userconf.dget('FGFW_Lite', 'logfile', ''):
            path = self.userconf.dget('FGFW_Lite', 'logfile', '')
            dirname = os.path.dirname(path)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
            formatter = logging.Formatter('FW-Lite %(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            hdlr = logging.handlers.RotatingFileHandler(path, maxBytes=1048576, backupCount=5)
            hdlr.setFormatter(formatter)
            self.logger.addHandler(hdlr)

        self.region = set(x.upper() for x in self.userconf.dget('fgfwproxy', 'region', '').split('|') if x.strip())
        self.profiles = len(self.userconf.dget('fgfwproxy', 'profile', '13'))
        self.xheaders = self.userconf.dgetbool('fgfwproxy', 'xheaders', False)

        if self.userconf.dget('fgfwproxy', 'parentproxy', ''):
            self.addparentproxy('direct', '%s 0' % self.userconf.dget('fgfwproxy', 'parentproxy', ''))
            self.addparentproxy('local', 'direct 100')
        else:
            self.addparentproxy('direct', 'direct 0')

        ParentProxy.set_via(self.parentlist.direct)

        for k, v in self.userconf.items('parents'):
            if '6Rc59g0jFlTppvel' in v:
                self.userconf.remove_option('parents', k)
                self.confsave()
                continue
            self.addparentproxy(k, v)

        if not self.rproxy and len([k for k in self.parentlist.httpsparents() if k.httpspriority < 100]) == 0:
            self.addparentproxy('shadowsocks_0', 'ss://aes-128-cfb:6Rc59g0jFlTppvel@155.254.32.50:8000')

        self.maxretry = self.userconf.dgetint('fgfwproxy', 'maxretry', 4)

        self.goagent = goagentHandler(self)

        def addhost(host, ip):
            try:
                ipo = get_ip_address(ip)
                if isinstance(ipo, IPv4Address):
                    self.HOSTS[host].append((2, ip))
                else:
                    self.HOSTS[host].append((10, ip))
            except Exception:
                self.logging.warning('unsupported host: %s' % ip)

        for host, ip in self.userconf.items('hosts'):
            addhost(host, ip)

        if os.path.isfile('./fgfw-lite/hosts'):
            for line in open('./fgfw-lite/hosts'):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ip, host = line.split()
                        addhost(host, ip)
                    except Exception as e:
                        self.logger.warning('%s %s' % (e, line))

        self.REDIRECTOR = redirector(self)
        self.PARENT_PROXY = parent_proxy(self)

    def reload(self):
        self.version.read('version.ini')
        self.userconf.read('userconf.ini')

    def confsave(self):
        with open('version.ini', 'w') as f:
            self.version.write(f)
        with open('userconf.ini', 'w') as f:
            self.userconf.write(f)

    def addparentproxy(self, name, proxy):
        self.parentlist.addstr(name, proxy)
        self.logger.info('add parent: %s: %s' % (name, proxy))

    def stdout(self, text=b''):
        if self.GUI:
            sys.stdout.write(text + b'\n')
            sys.stdout.flush()


@atexit.register
def atexit_do():
    for item in FGFWProxyHandler.ITEMS:
        item.stop()


def main():
    conf = Config()
    Timer(10, updater, (conf, )).start()
    d = {'http': '127.0.0.1:%d' % conf.listen[1], 'https': '127.0.0.1:%d' % conf.listen[1]}
    urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler(d)))
    for i, level in enumerate(list(conf.userconf.dget('fgfwproxy', 'profile', '13'))):
        server = ThreadingHTTPServer((conf.listen[0], conf.listen[1] + i), ProxyHandler, conf=conf, level=int(level))
        t = Thread(target=server.serve_forever)
        t.start()
        # if not resolver.proxy and level >= 3:
        #     resolver.proxy = '127.0.0.1:%d' % (conf.listen[1] + i)
    if not resolver.proxy:
        resolver.proxy = ParentProxy('localhost', '127.0.0.1:%d' % conf.listen[1])
    if conf.userconf.dgetbool('dns', 'enable', False):
        ls = conf.userconf.dget('dns', 'localserver', '114.114.114.114:53')
        ls = (ls.rsplit(':', 1)[0], int(ls.rsplit(':', 1)[1]))
        rs = conf.userconf.dget('dns', 'remoteserver', '8.8.8.8:53')
        rs = (rs.rsplit(':', 1)[0], int(rs.rsplit(':', 1)[1]))
        listen = conf.userconf.dget('dns', 'listen', '127.0.0.1:53')
        listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))
        from dnsserver import Resolver, UDPDNSServer, DNSHandler, TCPDNSServer
        r = Resolver(ls, rs, 'http://127.0.0.1:%d' % conf.listen[1])
        server = UDPDNSServer(listen, DNSHandler, r)
        t = Thread(target=server.serve_forever)
        t.start()
        server = TCPDNSServer(listen, DNSHandler, r)
        t = Thread(target=server.serve_forever)
        t.start()
    conf.stdout()
    t.join()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
