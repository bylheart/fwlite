
from __future__ import print_function, division

import re
import time
import urlparse
import logging
from collections import defaultdict
from repoze.lru import lru_cache
from util import parse_hostport


class ExpiredError(Exception):
    def __init__(self, rule):
        self.rule = rule


class ap_rule(object):
    def __init__(self, rule, msg=None, expire=None):
        super(ap_rule, self).__init__()
        self.rule = rule.strip()
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or '#' in self.rule:
            raise ValueError("invalid abp_rule: %s" % self.rule)
        self.msg = msg
        self.expire = expire
        self.override = self.rule.startswith('@@')
        self.logger = logging.getLogger('FW_Lite')
        self.logger.debug('parsing autoproxy rule: %r' % self.rule)
        self._regex = self._parse()

    def _parse(self):
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

        return parse(self.rule[2:]) if self.override else parse(self.rule)

    def match(self, uri):
        if self.expire and self.expire < time.time():
            raise ExpiredError(self)
        return self._regex.search(uri)

    def __repr__(self):
        return '<ap_rule>: %s' % self.rule


class ap_filter(object):
    KEYLEN = 6

    def __init__(self, lst=None):
        self.excludes = []
        self.matches = []
        self.domains = set()
        self.domain_endswith = tuple()
        self.exclude_domains = set()
        self.exclude_domain_endswith = tuple()
        self.url_startswith = tuple()
        self.fast = defaultdict(list)
        if lst:
            for rule in lst:
                self.add(rule)

    def add(self, rule):
        rule = rule.strip()
        if len(rule) < 3 or rule.startswith(('!', '[')) or '#' in rule:
            return
        if '*' not in rule:
            if rule.startswith('||'):
                return self._add_domain(rule)
            if rule.startswith('@@||'):
                return self._add_exclude_domain(rule)
        if rule.startswith(('|https://', '@', '/')):
            return self._add_slow(rule)
        if rule.startswith('|http://') and '*' not in rule:
            return self._add_urlstartswith(rule)
        if any(len(s) > (self.KEYLEN) for s in rule.split('*')):
            return self._add_fast(rule)
        self._add_slow(rule)

    def _add_urlstartswith(self, rule):
        temp = set(self.url_startswith)
        temp.add(rule[1:])
        self.url_startswith = tuple(temp)

    def _add_fast(self, rule):
        lst = [s for s in rule.split('*') if len(s) > self.KEYLEN]
        o = ap_rule(rule)
        key = lst[-1][self.KEYLEN * -1:]
        self.fast[key].append(o)

    def _add_slow(self, rule):
        try:
            o = ap_rule(rule)
            lst = self.excludes if o.override else self.matches
            lst.append(o)
        except TypeError:
            logging.warning(rule)

    def _add_exclude_domain(self, rule):
        rule = rule.rstrip('/')
        self.exclude_domains.add(rule[4:])
        temp = set(self.exclude_domain_endswith)
        temp.add('.' + rule[4:])
        self.exclude_domain_endswith = tuple(temp)

    def _add_domain(self, rule):
        rule = rule.rstrip('/')
        self.domains.add(rule[2:])
        temp = set(self.domain_endswith)
        temp.add('.' + rule[2:])
        self.domain_endswith = tuple(temp)

    def match(self, url, host=None):
        if host is None:
            if '://' in url:
                host = urlparse.urlparse(url).hostname
            else:  # www.google.com:443
                host = parse_hostport(url)[0]
        if self._listmatch(self.excludes, url):
            return False
        if self._domainmatch(host) is not None:
            return self._domainmatch(host)
        if url.startswith(self.url_startswith):
            return True
        if self._fastmatch(url):
            return True
        if self._listmatch(self.matches, url):
            return True

    @lru_cache(1024, timeout=30)
    def _domainmatch(self, host):
        if host in self.exclude_domains:
            return False
        if host.endswith(self.exclude_domain_endswith):
            return False
        if host in self.domains:
            return True
        if host.endswith(self.domain_endswith):
            return True

    def _fastmatch(self, url):
        if url.startswith('http://'):
            i, j = 0, self.KEYLEN
            while j < len(url):
                s = url[i:j]
                if s in self.fast:
                    if self._listmatch(self.fast[s], url):
                        return True
                i, j = i + 1, j + 1

    def _listmatch(self, lst, url):
        return any(r.match(url) for r in lst)

    def remove(self, rule):
        pass

if __name__ == "__main__":
    import sys
    import base64
    t = time.time()
    gfwlist = ap_filter()
    with open('gfwlist.txt') as f:
        data = f.read()
        if '!' not in data:
            data = ''.join(data.split())
            data = base64.b64decode(data).decode()
            for line in data.splitlines():
                # if line.startswith('||'):
                gfwlist.add(line)
            del data
    print('loading: %fs' % (time.time() - t))
    print('result for inxian: %r' % gfwlist.match('http://www.inxian.com', 'www.inxian.com'))
    print('result for twitter: %r' % gfwlist.match('www.twitter.com:443', 'www.twitter.com'))
    print('result for 163: %r' % gfwlist.match('http://www.163.com', 'www.163.com'))
    print('result for alipay: %r' % gfwlist.match('www.alipay.com:443', 'www.alipay.com'))
    print('result for qq: %r' % gfwlist.match('http://www.qq.com', 'www.qq.com'))
    print('result for keyword: %r' % gfwlist.match('http://www.test.com/iredmail.org', 'www.test.com'))
    print('result for url_startswith: %r' % gfwlist.match('http://itweet.net/whatever', 'itweet.net'))
    url = sys.argv[1] if len(sys.argv) > 1 else 'http://www.163.com'
    host = urlparse.urlparse(url).hostname
    print('%s, %s' % (url, host))
    print(gfwlist.match(url, host))
    t = time.time()
    for _ in range(10000):
        gfwlist.match(url, host)
    print('KEYLEN = %d' % gfwlist.KEYLEN)
    print('10000 query for %s, %fs' % (url, time.time() - t))
    print('O(1): %d' % (len(gfwlist.domains) + len(gfwlist.exclude_domains)))
    print('O(n): %d' % (len(gfwlist.excludes) + len(gfwlist.matches)))
    l = gfwlist.fast.keys()
    l = sorted(l, key=lambda x: len(gfwlist.fast[x]))
    for i in l[-20:]:
        print('%r : %d' % (i, len(gfwlist.fast[i])))
