#!/usr/bin/env python
# coding:utf-8
import sys
import time
import traceback
import pygeoip
from threading import Timer
try:
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
except ImportError:
    import urlparse
    import urllib2
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote
geoip = pygeoip.GeoIP('./goagent/GeoIP.dat')


class ParentProxy(object):
    via = ''
    DEFAULT_TIMEOUT = 4

    def __init__(self, name, proxy):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087 <optional int: httppriority> <optional int: httpspriority>"
        '''
        proxy, _, priority = proxy.partition(' ')
        httppriority, _, httpspriority = priority.partition(' ')
        httpspriority, _, timeout = httpspriority.partition(' ')
        httppriority = httppriority or 99
        httpspriority = httpspriority or httppriority
        timeout = timeout or self.DEFAULT_TIMEOUT

        if proxy == 'direct':
            proxy = ''
        elif proxy and '//' not in proxy:
            proxy = 'http://' + proxy
        self.name = name
        self.proxy = proxy
        self.parse = urlparse.urlparse(self.proxy)
        self.httppriority = int(httppriority)
        self.httpspriority = int(httpspriority)
        self.timeout = int(timeout)
        self.country_code = None
        self.last_ckeck = 0
        if self.parse.scheme.lower() == 'sni':
            self.httppriority = -1

    def get_location(self):
        if time.time() - self.last_ckeck < 60:
            return
        from connection import create_connection
        from httputil import read_reaponse_line, read_headers, read_header_data
        try:
            soc = create_connection(('bot.whatismyipaddress.com', 80), ctimeout=None, parentproxy=self, via=self.via)
            soc.sendall(b'GET / HTTP/1.0\r\nHost: bot.whatismyipaddress.com\r\n\r\n')
            f = soc.makefile()
            line, version, status, reason = read_reaponse_line(f)
            _, headers = read_headers(f)
            assert status == 200
            ip = soc.recv(int(headers['Content-Length']))
            self.country_code = geoip.country_code_by_addr(ip)
            soc.close()
        except Exception as e:
            sys.stderr.write(repr(e))
            sys.stderr.write('\n')
            sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
        self.last_ckeck = time.time()

    @property
    def scheme(self):
        return self.parse.scheme

    @property
    def username(self):
        return urlunquote(self.parse.username) if self.parse.username else None

    @property
    def password(self):
        return urlunquote(self.parse.password) if self.parse.password else None

    @property
    def hostname(self):
        return self.parse.hostname

    @property
    def port(self):
        return self.parse.port

    @classmethod
    def set_via(cls, proxy):
        cls.via = proxy

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<ParentProxy: %s %s %s>' % (self.name or 'direct', self.httppriority, self.httpspriority)


class ParentProxyList(object):
    def __init__(self):
        self.direct = None
        self.local = None
        self._httpparents = set()
        self._httpsparents = set()
        self.badproxys = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy))

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        self.dict[parentproxy.name] = parentproxy
        if parentproxy.name == 'direct':
            self.direct = parentproxy
            return
        if parentproxy.name == 'local':
            self.local = parentproxy
            return
        if parentproxy.httppriority >= 0:
            self._httpparents.add(parentproxy)
        if parentproxy.httpspriority >= 0:
            self._httpsparents.add(parentproxy)

    def remove(self, name):
        if name == 'direct' or name not in self.dict:
            return 1
        a = self.dict.get(name)
        del self.dict[name]
        self._httpparents.discard(a)
        self._httpsparents.discard(a)

    def httpparents(self):
        return list(self._httpparents - self.badproxys)

    def httpsparents(self):
        return list(self._httpsparents - self.badproxys)

    def report_bad(self, ppname):
        if ppname in self.dict:
            self.badproxys.add(self.dict[ppname])
            Timer(600, self.badproxys.discard, (self.dict[ppname], )).start()
