#!/usr/bin/env python
# coding: UTF-8
import os
import re
try:
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
except ImportError:
    import urllib2
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote

if not os.path.isfile('./fgfw-lite/_redirector.py'):
    with open('./fgfw-lite/_redirector.py', 'w') as f:
        f.write('''\
#!/usr/bin/env python
# coding: UTF-8
# This file is designed for expirenced user to edit


def redirector(handler):
    pass
''')
from apfilter import ap_rule, ap_filter
from _redirector import redirector as uredirector


class redirector(object):
    def __init__(self, conf):
        self.conf = conf
        self.logger = conf.logger
        self._bad302 = ap_filter()
        self.adblock = ap_filter()
        self.redirlst = []

    def redirect(self, hdlr):
        searchword = re.match(r'^http://([\w-]+)/$', hdlr.path)
        if searchword:
            q = searchword.group(1)
            if 'xn--' in q:
                q = q.encode().decode('idna')
            self.logger.debug('Match redirect rule addressbar-search')
            return 'https://www.google.com/search?q=%s&ie=utf-8&oe=utf-8' % urlquote(q.encode('utf-8'))
        for rule, result in self.redirlst:
            if rule.match(hdlr.path):
                self.logger.debug('Match redirect rule {}, {}'.format(rule.rule, result))
                if rule.override:
                    return None
                if result == 'forcehttps':
                    return hdlr.path.replace('http://', 'https://', 1)
                if result.startswith('/') and result.endswith('/'):
                    return rule._regex.sub(result[1:-1], hdlr.path)
                return result
        if self.adblock.match(hdlr.path):
            return 'adblock'
        return uredirector(hdlr)

    def bad302(self, uri):
        return self._bad302.match(uri)

    def add_redirect(self, rule, dest, pp=None):
        if pp is None:
            pp = self.conf.PARENT_PROXY
        try:
            if rule in [a.rule for a, b in self.redirlst]:
                self.logger.warning('multiple redirector rule! %s' % rule)
                return
            if dest.lower() == 'auto':
                return pp.add_ignore(rule)
            if dest.lower() == 'bad302':
                return self._bad302.add(rule)
            if dest.lower() == 'adblock':
                return self.adblock.add(rule)
            self.redirlst.append((ap_rule(rule), dest))
        except ValueError as e:
            self.logger.debug('create autoproxy rule failed: %s' % e)
