#!/usr/bin/env python
# coding:utf-8
from threading import Timer
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse


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
        self.name = name
        self.proxy = proxy
        self.parse = urlparse.urlparse(self.proxy)
        self.httppriority = int(httppriority)
        self.httpspriority = int(httpspriority)
        self.timeout = int(timeout)
        if self.parse.scheme.lower() == 'sni':
            self.httppriority = -1

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<ParentProxy: %s %s %s>' % (self.name or 'direct', self.httppriority, self.httpspriority)


class ParentProxyList(object):
    def __init__(self, default_timeout):
        self.default_timeout = default_timeout
        self._httpparents = set()
        self._httpsparents = set()
        self.badproxys = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy, self.default_timeout))

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        if parentproxy.httppriority >= 0:
            self._httpparents.add(parentproxy)
        if parentproxy.httpspriority >= 0:
            self._httpsparents.add(parentproxy)
        self.dict[parentproxy.name] = parentproxy

    def remove(self, name):
        a = self.dict.get(name)
        if not a or name == 'direct':
            return 1
        try:
            self.httpparents.remove(a)
        finally:
            try:
                self.httpsparents.remove(a)
            except:
                pass

    def httpparents(self):
        return list(self._httpparents - self.badproxys)

    def httpsparents(self):
        return list(self._httpsparents - self.badproxys)

    def report_bad(self, ppname):
        if ppname in self.dict:
            self.badproxys.add(self.dict[ppname])
            Timer(600, self.badproxys.discard, (self.dict[ppname])).start()
