#!/usr/bin/env python

import os
import sys
import socket
import logging
from collections import defaultdict

try:
    from ipaddress import IPv4Address, ip_address
except:
    from ipaddr import IPv4Address
    from ipaddr import IPAddress as ip_address

from parent_proxy import ParentProxyList, ParentProxy
from get_proxy import get_proxy
from redirector import redirector
from util import SConfigParser, parse_hostport
import resolver


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

        def addhost(host, ip):
            try:
                ipo = ip_address(ip)
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
        self.localdns = parse_hostport(self.userconf.dget('dns', 'localdns', '114.114.114.114:53'))
        self.remotedns = parse_hostport(self.userconf.dget('dns', 'remotedns', '8.8.8.8:53'))
        self.REDIRECTOR = redirector(self)
        self.PARENT_PROXY = get_proxy(self)
        self.resolver = resolver.get_resolver(self.localdns, self.remotedns,
                                              'http://127.0.0.1:%d' % self.listen[1],
                                              self.PARENT_PROXY.force)

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

conf = Config()
