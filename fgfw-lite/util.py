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

import re
import errno
import socket
import select
import logging
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

logger = logging.getLogger('FW_Lite')


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


def forward_socket(local, remote, timeout, bufsize):
    """forward socket"""
    try:
        while 1:
            ins, _, _ = select.select([local, remote], [], [], timeout)
            if not ins:
                break
            if local in ins:
                data = local.recv(bufsize)
                if not data:
                    break
                remote.sendall(data)
            if remote in ins:
                data = remote.recv(bufsize)
                if not data:
                    break
                local.sendall(data)
    except socket.timeout:
        pass
    except (OSError, IOError) as e:
        if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
            raise
        if e.args[0] in (errno.EBADF,):
            return
    finally:
        for sock in (remote, local):
            try:
                sock.close()
            except (OSError, IOError):
                pass


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def is_connection_dropped(lst):  # modified from urllib3
    """
    Returns sockets if the connection is dropped and should be closed.

    """
    try:
        return select.select(lst, [], [], 0.0)[0]
    except IOError:
        return lst


def sizeof_fmt(num):
    if num < 1024:
        return "%dB" % num
    for x in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return "%.1f%s" % (num, x)
        num /= 1024.0
    return "%.1f%s" % (num, 'TB')


if __name__ == "__main__":
    pass
