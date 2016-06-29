#!/usr/bin/env python
# coding: UTF-8
#
import sys
import io
import itertools
import logging
from threading import RLock, Timer
from collections import defaultdict, deque
try:
    from http.client import HTTPMessage
    import email
except ImportError:
    from httplib import HTTPMessage
from util import is_connection_dropped


def read_reaponse_line(fp):
    line = fp.readline()
    if not line.startswith(b'HTTP'):
        raise IOError(0, 'bad response line: %r' % line)
    version, _, status = line.strip().partition(b' ')
    status, _, reason = status.partition(b' ')
    status = int(status)
    return line, version, status, reason


def read_header_data(fp):
    header_data = []
    while True:
        line = fp.readline()
        header_data.append(line)
        if line in (b'\r\n', b'\n', b'\r'):  # header ends with a empty line
            break
        if not line:
            raise IOError(0, 'remote socket closed')
    return b''.join(header_data)


def read_headers(fp):
    header_data = read_header_data(fp)
    headers = parse_headers(header_data)
    return header_data, headers


def parse_headers(data):
    if sys.version_info > (3, 0):
        return email.parser.Parser(_class=HTTPMessage).parsestr(data.decode('iso-8859-1'))
    else:
        fp = io.StringIO(data.decode('iso-8859-1'))
        return HTTPMessage(fp, 0)


class httpconn_pool(object):
    def __init__(self):
        self.POOL = defaultdict(deque)  # {upstream_name: [(soc, ppname), ...]}
        self.socs = {}  # keep track of sock info
        self.timerwheel = [set() for _ in range(10)]  # a list of socket object
        self.timerwheel_iter = itertools.cycle(range(10))
        self.timerwheel_index = next(self.timerwheel_iter)
        self.lock = RLock()
        self.logger = logging.getLogger('httpconn_pool')
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        Timer(30, self._purge, ()).start()

    def put(self, upstream_name, soc, ppname):
        with self.lock:
            self.POOL[upstream_name].append((soc, ppname))
            self.socs[soc] = (self.timerwheel_index, ppname, upstream_name)
            self.timerwheel[self.timerwheel_index].add(soc)

    def get(self, upstream_name):
        with self.lock:
            lst = self.POOL.get(upstream_name)
            while lst:
                sock, pproxy = lst.popleft()
                if is_connection_dropped([sock]):
                    sock.close()
                    self._remove(sock)
                    continue
                self._remove(sock)
                return (sock, pproxy)

    def _remove(self, soc):
        twindex, ppn, upsname = self.socs.pop(soc)
        self.timerwheel[twindex].discard(soc)
        if (soc, ppn) in self.POOL[upsname]:
            self.POOL[upsname].remove((soc, ppn))

    def _purge(self):
        pcount = 0
        with self.lock:
            for soc in is_connection_dropped(self.socs.keys()):
                soc.close()
                self._remove(soc)
                pcount += 1
            self.timerwheel_index = next(self.timerwheel_iter)
            for soc in list(self.timerwheel[self.timerwheel_index]):
                soc.close()
                self._remove(soc)
                pcount += 1
        if pcount:
            self.logger.debug('%d remotesoc purged, %d in connection pool.(%s)' % (pcount, len(self.socs), ', '.join([k[0] if isinstance(k, tuple) else k for k, v in self.POOL.items() if v])))
        Timer(30, self._purge, ()).start()
