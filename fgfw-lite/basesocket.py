#!/usr/bin/env python
# coding:utf-8
import io
import errno
import socket


class basesocket(object):
    bufsize = 8192

    def __init__(self):
        self._rbuffer = io.BytesIO()
        self._sock = None

    def readline(self, size=-1):
        buf = self._rbuffer
        buf.seek(0, 2)  # seek end
        if buf.tell() > 0:
            # check if we already have it in our buffer
            buf.seek(0)
            bline = buf.readline(size)
            if bline.endswith('\n') or len(bline) == size:
                self._rbuffer = io.BytesIO()
                self._rbuffer.write(buf.read())
                return bline
            del bline
        if size < 0:
            # Read until \n or EOF, whichever comes first
            buf.seek(0, 2)  # seek end
            self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                nl = data.find(b'\n')
                if nl >= 0:
                    nl += 1
                    buf.write(data[:nl])
                    self._rbuffer.write(data[nl:])
                    break
                buf.write(data)
            del data
            return buf.getvalue()
        else:
            # Read until size bytes or \n or EOF seen, whichever comes first
            buf.seek(0, 2)  # seek end
            buf_len = buf.tell()
            if buf_len >= size:
                buf.seek(0)
                rv = buf.read(size)
                self._rbuffer = io.BytesIO()
                self._rbuffer.write(buf.read())
                return rv
            self._rbuffer = io.BytesIO()  # reset _rbuf.  we consume it via buf.
            while True:
                try:
                    data = self.recv(self.bufsize)
                except socket.error as e:
                    if e.args[0] == errno.EINTR:
                        continue
                    raise
                if not data:
                    break
                left = size - buf_len
                # did we just receive a newline?
                nl = data.find(b'\n', 0, left)
                if nl >= 0:
                    nl += 1
                    # save the excess data to _rbuf
                    self._rbuffer.write(data[nl:])
                    if buf_len:
                        buf.write(data[:nl])
                        break
                    else:
                        # Shortcut.  Avoid data copy through buf when returning
                        # a substring of our first recv().
                        return data[:nl]
                n = len(data)
                if n == size and not buf_len:
                    # Shortcut.  Avoid data copy through buf when
                    # returning exactly all of our first recv().
                    return data
                if n >= left:
                    buf.write(data[:left])
                    self._rbuffer.write(data[left:])
                    break
                buf.write(data)
                buf_len += n
                # assert buf_len == buf.tell()
            return buf.getvalue()

    def close(self):
        if self._sock:
            self._sock.close()

    def __del__(self):
        self.close()

    def settimeout(self, value):
        return self._sock.settimeout(value)

    def setsockopt(self, level, optname, value):
        return self._sock.setsockopt(level, optname, value)

    def fileno(self):
        return self._sock.fileno()

    def shutdown(self, how):
        return self._sock.shutdown(how)

    def connect(self, address):
        raise NotImplementedError

    def recv(self, size):
        raise NotImplementedError

    def sendall(self, data):
        raise NotImplementedError

    def makefile(self, mode='rb', bufsize=0):
        raise NotImplementedError
