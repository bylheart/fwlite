#!/usr/bin/env python
# coding: UTF-8
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

from collections import OrderedDict, defaultdict
import re
import random
import select
import time
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
try:
    import geoip2.database
except ImportError:
    geoip2 = None

configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    optionxform = str

    def dget(self, section, option, default=''):
        try:
            value = self.get(section, option)
            if not value:
                value = default
        except Exception:
            value = default
        return value

    def dgetfloat(self, section, option, default=0):
        try:
            return self.getfloat(section, option)
        except Exception:
            return float(default)

    def dgetint(self, section, option, default=0):
        try:
            return self.getint(section, option)
        except Exception:
            return int(default)

    def dgetbool(self, section, option, default=False):
        try:
            return self.getboolean(section, option)
        except Exception:
            return bool(default)

    def items(self, section):
        try:
            return configparser.ConfigParser.items(self, section)
        except Exception:
            return []

    def set(self, section, option, value):
        if not self.has_section(section):
            self.add_section(section)
        configparser.ConfigParser.set(self, section, option, value)


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def is_connection_dropped(lst):  # modified from urllib3
    """
    Returns sockets that is dropped and should be closed.

    """
    try:
        return select.select(lst, [], [], 0.0)[0]
    except Exception:
        return lst


def sizeof_fmt(num):
    if num < 1024:
        return "%dB" % num
    for x in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return "%.1f%s" % (num, x)
        num /= 1024.0
    return "%.1f%s" % (num, 'TB')


try:
    GeoIP2 = geoip2.database.Reader('./fgfw-lite/GeoLite2-Country.mmdb', mode=geoip2.database.MODE_MEMORY) if geoip2 else None
except Exception:
    GeoIP2 = geoip2.database.Reader('./GeoLite2-Country.mmdb', mode=geoip2.database.MODE_MEMORY)


def ip_to_country_code(ip):
    try:
        resp = GeoIP2.country(str(ip))
        return resp.country.iso_code
    except Exception:
        return u''


class iv_store(object):

    def __init__(self, maxlen, timeout):
        self.maxlen = maxlen
        self.timeout = timeout
        self.store = OrderedDict()
        self.last_time_used = time.time()

    def add(self, item):
        self.last_time_used = time.time()
        if random.random() < 0.01:
            self._clean()
        if item in self:
            raise ValueError("iv reused")
        self.store[item] = self.last_time_used
        while len(self.store) > self.maxlen:
            self.store.popitem()

    def __contains__(self, item):
        if random.random() < 0.01:
            self._clean()
        self.last_time_used = time.time()
        try:
            if self.store[item] < time.time() - self.timeout:
                while True:
                    a, _ = self.store.popitem()
                    if a == item:
                        break
                return False
            else:
                return True
        except KeyError:
            return False

    def _clean(self):
        garbage = []
        for k in self.store:
            if self.store[k] < time.time() - self.timeout:
                garbage.append(k)
            else:
                break
        for k in garbage:
            del self.store[k]

    def __str__(self):
        return str([k for k in self.store])

    def __repr__(self):
        return str([k for k in self.store])


class iv_checker(object):
    # check reused iv, removing out-dated data automatically

    def __init__(self, maxlen, timeout):
        self.timeout = timeout * 10
        self.store = defaultdict(lambda: iv_store(maxlen, timeout * 2))

    def check(self, key, iv):
        if random.random() < 0.01:
            self._clean()
        self.store[key].add(iv)

    def _clean(self):
        garbage = []
        for k, v in self.store.items():
            if v.last_time_used < time.time() - self.timeout:
                garbage.append(k)
        for k in garbage:
            del self.store[k]
