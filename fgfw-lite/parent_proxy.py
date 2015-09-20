#!/usr/bin/env python
# coding:utf-8
import sys
import time
import traceback
import socket
import logging
from threading import Timer
try:
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
    from ipaddress import ip_address
except ImportError:
    import urlparse
    import urllib2
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote
    from ipaddr import IPAddress as ip_address
from util import ip_to_country_code


class ParentProxy(object):
    via = None
    DEFAULT_TIMEOUT = 8

    def __init__(self, name, proxy):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087<|more proxies> <optional int: httppriority> <optional int: httpspriority>"
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
        proxy_list = proxy.split('|')
        self.proxy = proxy_list[0]
        if len(proxy_list) > 1:
            self.via = ParentProxy('via', '|'.join(proxy_list[1:]))
            self.via.name = '%s://%s:%s' % (self.via.scheme, self.via.hostname, self.via.port)
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
        ip = ip_address(socket.getaddrinfo(self.parse.hostname, 0)[0][4][0])

        if ip.is_loopback or ip.is_private:
            from connection import create_connection
            from httputil import read_reaponse_line, read_headers
            try:
                soc = create_connection(('bot.whatismyipaddress.com', 80), ctimeout=None, parentproxy=self)
                soc.sendall(b'GET / HTTP/1.1\r\nConnection: close\r\nHost: bot.whatismyipaddress.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0\r\n\r\n')
                f = soc.makefile()
                line, version, status, reason = read_reaponse_line(f)
                _, headers = read_headers(f)
                assert status == 200
                ip = soc.recv(int(headers['Content-Length']))
                if not ip:
                    soc.close()
                    raise ValueError('%s: ip address is empty' % self.name)
                self.country_code = ip_to_country_code(ip)
                soc.close()
            except Exception:
                sys.stderr.write(traceback.format_exc())
                sys.stderr.flush()
                self.country_code = None
        else:
            self.country_code = ip_to_country_code(ip)
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
        if parentproxy.parse.scheme:
            s = '%s://%s:%s' % (parentproxy.parse.scheme, parentproxy.parse.hostname, parentproxy.parse.port)
        else:
            s = 'None'
        logging.info('add parent: %s: %s' % (parentproxy.name, s))
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

    def get(self, key):
        return self.dict.get(key)
