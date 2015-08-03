#!/usr/bin/env python
# coding:utf-8
import base64
import datetime
import sqlite3
import logging
import random
import time
from threading import Timer

from repoze.lru import lru_cache

from apfilter import ap_rule, ap_filter, ExpiredError
from util import ip_to_country_code


class stats(object):
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("create table log (ts real, date text, command text, hostname text, url text, ppname text, success integer, time real)")
    logger = logging.getLogger('FW_Lite')

    def __init__(self, conf):
        self.conf = conf
        Timer(3600, self._purge, ()).start()

    def log(self, command, hostname, url, ppname, success, rtime):
        with self.con:
            self.con.execute('INSERT into log values (?,?,?,?,?,?,?,?)', (time.time(), datetime.date.today(), command, hostname, url, ppname, success, rtime))
        if not success:
            if self.is_bad_pp('direct') is False:  # if internet connection is good
                if self.is_bad_pp(ppname):
                    self.logger.info('Probable bad parent: %s, remove.' % ppname)
                    self.conf.parentlist.report_bad(ppname)

    def srbh(self, hostname, sincetime=None):
        '''success rate by hostname'''
        if sincetime is None:
            sincetime = time.time() - 10 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where hostname = (?) and ts >= (?)', (hostname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbp(self, ppname, sincetime=None):
        '''success rate by ppname'''
        if sincetime is None:
            sincetime = time.time() - 10 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where ppname = (?) and ts >= (?)', (ppname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbhp(self, hostname, ppname, sincetime=None):
        '''success rate by hostname and ppname'''
        if sincetime is None:
            sincetime = time.time() - 30 * 60
        r = next(self.con.execute('SELECT count(*), sum(success) from log where hostname = (?) and ppname = (?) and ts >= (?)', (hostname, ppname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def srbhwp(self, hostname, sincetime=None):
        '''success rate by hostname with a parentproxy'''
        if sincetime is None:
            sincetime = time.time() - 30 * 60
        r = next(self.con.execute("SELECT count(*), sum(success) from log where hostname = (?) and ppname <> 'direct' and ts >= (?)", (hostname, sincetime)))
        if r[0] == 0:
            return(1, 0)
        return (r[1] / r[0], r[0])

    def avg_time(self, ppname, hostname=None):
        sincetime = time.time() - 10 * 60
        if hostname:
            r = next(self.con.execute("SELECT count(*), sum(time) from log where hostname = (?) and ppname = (?) and ts >= (?) and success = 1 order by ts desc LIMIT 10", (hostname, ppname, sincetime)))
        else:
            r = next(self.con.execute("SELECT count(*), sum(time) from log where ppname = (?) and ts >= (?) and success = 1 order by ts desc LIMIT 50", (ppname, sincetime)))
        if r[0] == 0:
            return 1
        logging.debug('avg time %s via %s: %.3f' % (hostname, ppname, r[1] / r[0]))
        return r[1] / r[0]

    def is_bad_pp(self, ppname):
        '''if a given ppname is unavailable'''
        sincetime = time.time() - 10 * 60
        result = self.con.execute('SELECT success from log where ppname = (?) and ts >= (?) order by ts desc LIMIT 5', (ppname, sincetime))
        rsum = count = 0
        for s in result:
            rsum += s[0]
            count += 1
        self.logger.debug('%s %s %s %r' % (ppname, count, rsum, not rsum if count >= 5 else None))
        if count >= 5:
            return not rsum
        return None

    def _purge(self, befortime=None):
        if not befortime:
            befortime = time.time() - 24 * 60 * 60
        with self.con:
            self.con.execute('DELETE from log where ts < (?)', (befortime, ))
        Timer(3600, self._purge, ()).start()


ASIA = ('AE', 'AF', 'AL', 'AZ', 'BD', 'BH', 'BN', 'BT', 'CN', 'CY', 'HK', 'ID',
        'IL', 'IN', 'IQ', 'IR', 'JO', 'JP', 'KH', 'KP', 'KR', 'KW', 'KZ', 'LA',
        'LB', 'LU', 'MN', 'MO', 'MV', 'MY', 'NP', 'OM', 'PH', 'PK', 'QA', 'SA',
        'SG', 'SY', 'TH', 'TJ', 'TM', 'TW', 'UZ', 'VN', 'YE')
AFRICA = ('AO', 'BI', 'BJ', 'BW', 'CF', 'CG', 'CM', 'CV', 'DZ', 'EG', 'ET', 'GA', 'GH',
          'GM', 'GN', 'GQ', 'KE', 'LY', 'MA', 'MG', 'ML', 'MR', 'MU', 'MZ', 'NA', 'NE',
          'NG', 'RW', 'SD', 'SN', 'SO', 'TN', 'TZ', 'UG', 'ZA', 'ZM', 'ZR', 'ZW')
NA = ('BM', 'BS', 'CA', 'CR', 'CU', 'GD', 'GT', 'HN', 'HT', 'JM', 'MX', 'NI', 'PA', 'US', 'VE')
SA = ('AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'GY', 'PE', 'PY', 'UY')
EU = ('AT', 'BE', 'BG', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GB',
      'GR', 'HR', 'HU', 'IE', 'IS', 'IT', 'LT', 'LV', 'MC', 'MD', 'MT', 'NL',
      'NO', 'PL', 'PT', 'RO', 'RU', 'SE', 'SK', 'SM', 'UA', 'UK', 'VA', 'YU')
PACIFIC = ('AU', 'CK', 'FJ', 'GU', 'NZ', 'PG', 'TO')

continent_list = [ASIA, AFRICA, NA, SA, EU, PACIFIC]


class get_proxy(object):
    """docstring for parent_proxy"""
    def __init__(self, conf):
        self.conf = conf
        self.logger = self.conf.logger
        self.config()
        self.STATS = stats(self.conf)

    def config(self):
        self.gfwlist = ap_filter()
        self.force = ap_filter()
        self.temp = []
        self.temp_rules = set()
        self.ignore = []

        for line in open('./fgfw-lite/local.txt'):
            rule, _, dest = line.strip().partition(' ')
            if dest:  # |http://www.google.com/url forcehttps
                self.add_redirect(rule, dest)
            else:
                self.add_temp(line, quiet=True)

        if self.conf.rproxy is False:
            for line in open('./fgfw-lite/cloud.txt'):
                rule, _, dest = line.strip().partition(' ')
                if dest:  # |http://www.google.com/url forcehttps
                    self.add_redirect(rule, dest)
                else:
                    self.add_rule(line, force=True)

            self.logger.info('loading  gfwlist...')
            try:
                with open('./fgfw-lite/gfwlist.txt') as f:
                    data = f.read()
                    if '!' not in data:
                        data = ''.join(data.split())
                        data = base64.b64decode(data).decode()
                    for line in data.splitlines():
                        self.add_rule(line)
            except:
                self.logger.warning('./fgfw-lite/gfwlist.txt is corrupted!')

            if self.conf.userconf.dgetbool('fgfwproxy', 'adblock', False):
                self.logger.info('loading adblock...')
                try:
                    with open('./fgfw-lite/adblock.txt') as f:
                        data = f.read()
                        for line in data.splitlines():
                            if line.startswith('||') and line.endswith('^'):
                                self.add_redirect(line, 'adblock')
                except:
                    self.logger.warning('./fgfw-lite/adblock.txt is corrupted!')

    def redirect(self, hdlr):
        return self.conf.REDIRECTOR.redirect(hdlr)

    def add_redirect(self, rule, dest):
        return self.conf.REDIRECTOR.add_redirect(rule, dest, self)

    def bad302(self, uri):
        return self.conf.REDIRECTOR.bad302(uri)

    def add_ignore(self, rule):
        self.ignore.append(ap_rule(rule))

    def add_rule(self, line, force=False):
        try:
            if '||' in line:
                self.force.add(line)
            elif force:
                self.force.add(line)
            else:
                self.gfwlist.add(line)
        except ValueError as e:
            self.logger.debug('create autoproxy rule failed: %s' % e)

    @lru_cache(256, timeout=120)
    def ifhost_in_region(self, host, ip):
        try:
            code = ip_to_country_code(ip)
            if code in self.conf.region:
                self.logger.info('%s in %s' % (host, code))
                return True
            return False
        except:
            pass

    def if_temp(self, uri):
        for rule in self.temp:
            try:
                if rule.match(uri):
                    return not rule.override
            except ExpiredError:
                self.logger.info('%s expired' % rule.rule)
                self.conf.stdout()
                self.temp.remove(rule)
                self.temp_rules.discard(rule.rule)

    def ifgfwed(self, uri, host, port, ip, level=1):
        if level == 0:
            return False

        if self.conf.rproxy:
            return None

        if ip is None:
            return True

        if ip and any((ip.is_loopback, ip.is_private)):
            return False

        if level == 4:
            return True

        a = self.if_temp(uri)
        if a is not None:
            return a

        a = self.force.match(uri, host)
        if a is not None:
            return a

        if any(rule.match(uri) for rule in self.ignore):
            return None

        if level == 2 and uri.startswith('http://'):
            return True

        if self.conf.HOSTS.get(host) or self.ifhost_in_region(host, str(ip)):
            return None

        if level == 3:
            return True

        if self.conf.userconf.dgetbool('fgfwproxy', 'gfwlist', True) and self.gfwlist.match(uri):
            return True

    def parentproxy(self, uri, host, command, ip, level=1, nogoagent=False):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443) (no port number is allowed)
            level: 0 -- direct
                   1 -- auto:        proxy if force, direct if ip in region or override, proxy if gfwlist
                   2 -- encrypt all: proxy if force or not https, direct if ip in region or override, proxy if gfwlist
                   3 -- chnroute:    proxy if force, direct if ip in region or override, proxy if all
                   4 -- global:      proxy if not local
        '''
        host, port = host

        ifgfwed = self.ifgfwed(uri, host, port, ip, level)

        if ifgfwed is False:
            if ip and ip.is_private:
                return [self.conf.parentlist.local or self.conf.parentlist.direct]
            return [self.conf.parentlist.direct]

        parentlist = list(self.conf.parentlist.httpsparents() if command == 'CONNECT' else self.conf.parentlist.httpparents())
        if len(parentlist) < self.conf.maxretry:
            parentlist.extend(parentlist[1:] if not ifgfwed else parentlist)
            parentlist = parentlist[:self.conf.maxretry]

        def priority(parent):
            priority = parent.httpspriority if command == 'CONNECT' else parent.httppriority
            avg_time = self.STATS.avg_time(parent.name, host)
            if not ip:
                return priority + avg_time * 10
            result = priority
            if parent.country_code is None:
                parent.get_location()
            if parent.country_code is None:
                result = priority + 3
            parent_cc = parent.country_code
            dest = ''
            dest = ip_to_country_code(ip)
            if parent_cc == dest:
                result = priority - 3
            else:
                for continent in continent_list:
                    if parent_cc in continent and dest in continent:
                        result = priority - 1
                        break
            return result + avg_time * 10

        if len(parentlist) > 1:
            random.shuffle(parentlist)
            parentlist = sorted(parentlist, key=priority)

        if nogoagent and self.conf.parentlist.get('goagent') in parentlist:
            parentlist.remove(self.conf.parentlist.get('goagent'))

        if ifgfwed:
            if not parentlist:
                self.logger.warning('No parent proxy available, direct connection is used')
                return [self.conf.parentlist.get('direct')]
        else:
            parentlist.insert(0, self.conf.parentlist.direct)

        if len(parentlist) == 1 and parentlist[0] is self.conf.parentlist.get('direct'):
            return parentlist

        if len(parentlist) > self.conf.maxretry:
            parentlist = parentlist[:self.conf.maxretry]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent, time=0):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s' % (command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None'))
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if success:
            for fpp in failed_parents:
                self.STATS.log(command, requesthost[0], url, fpp, 0, 0)
            if current_parent:
                self.STATS.log(command, requesthost[0], url, current_parent, success, time)
            if 'direct' in failed_parents:
                if command == 'CONNECT':
                    rule = '|https://%s' % requesthost[0]
                else:
                    rule = '|http://%s' % requesthost[0] if requesthost[1] == 80 else '%s:%d' % requesthost
                if rule not in self.temp_rules:
                    direct_sr = self.STATS.srbhp(requesthost[0], 'direct')
                    if direct_sr[1] < 2:
                        exp = 1
                    elif direct_sr[0] < 0.1:
                        exp = min(pow(direct_sr[1], 1.5), 60)
                    elif direct_sr[0] < 0.5:
                        exp = min(direct_sr[1], 10)
                    else:
                        exp = 1
                    self.add_temp(rule, exp)
                    self.conf.stdout()

    def add_temp(self, rule, exp=None, quiet=False):
        rule = rule.strip()
        if rule not in self.temp_rules:
            try:
                if not quiet:
                    self.logger.info('add autoproxy rule: %s%s' % (rule, (' expire in %.1f min' % exp) if exp else ''))
                self.temp.append(ap_rule(rule, expire=None if not exp else (time.time() + 60 * exp)))
                self.temp_rules.add(rule)
            except ValueError:
                pass
        else:
            return 'already in there'
