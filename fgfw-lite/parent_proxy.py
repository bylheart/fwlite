#!/usr/bin/env python
# coding:utf-8
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse


class ParentProxy(object):
    def __init__(self, name, proxy, default_timeout):
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

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy, self.default_timeout))
