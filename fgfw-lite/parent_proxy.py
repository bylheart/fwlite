#!/usr/bin/env python
# coding:utf-8
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
    def __init__(self, name, proxy, default_timeout=4):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087 <optional int: httppriority> <optional int: httpspriority>"
        '''
        proxy, _, priority = proxy.partition(' ')
        httppriority, _, httpspriority = priority.partition(' ')
        httpspriority, _, timeout = httpspriority.partition(' ')
        httppriority = httppriority or 99
        httpspriority = httpspriority or httppriority
        timeout = timeout or default_timeout

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
        try:
            self.country_code = geoip.country_code_by_name(self.parse.hostname)
        except:
            self.country_code = None
        if self.parse.scheme.lower() == 'sni':
            self.httppriority = -1

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

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<ParentProxy: %s %s %s>' % (self.name or 'direct', self.httppriority, self.httpspriority)


class ParentProxyList(object):
    def __init__(self, default_timeout):
        self.default_timeout = default_timeout
        self.direct = None
        self.local = None
        self._httpparents = set()
        self._httpsparents = set()
        self.badproxys = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy, self.default_timeout))

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
