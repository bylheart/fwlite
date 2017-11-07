#!/usr/bin/env python

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import logging
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, c_uint, byref, \
    create_string_buffer, c_void_p

logger = logging.getLogger('ctypes_libsodium')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

__all__ = ['ciphers']

libsodium = None
loaded = False

buf_size = 8196

# for salsa20 and chacha20
BLOCK_SIZE = 64


def load_libsodium():
    global loaded, libsodium, buf

    from ctypes.util import find_library

    if os.name == "nt" and os.path.isfile('./Python27/libsodium.dll'):
        libsodium_path = './Python27/libsodium.dll'
    else:
        for p in ('sodium', 'libsodium', ):
            libsodium_path = find_library(p)
            if libsodium_path:
                break
    if not libsodium_path:
        raise IOError(0, 'libsodium not found')
    logger.info('loading libsodium from %s' % libsodium_path)
    libsodium = CDLL(libsodium_path)
    libsodium.sodium_init.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                       c_ulonglong,
                                                       c_char_p, c_ulonglong,
                                                       c_char_p)
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulonglong,
                                                        c_char_p)

    libsodium.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_ietf_xor_ic.argtypes = (
        c_void_p, c_char_p,
        c_ulonglong,
        c_char_p,
        c_uint,  # uint32_t initial counter
        c_char_p
    )

    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p,
        c_char_p, c_char_p
    )
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p, c_char_p
    )

    libsodium.sodium_init()

    buf = create_string_buffer(buf_size)
    loaded = True


class SodiumCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_libsodium()
        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)
        if cipher_name == 'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        elif cipher_name == 'chacha20-ietf':
            self.cipher = libsodium.crypto_stream_chacha20_ietf_xor_ic
        else:
            raise Exception('Unknown cipher')
        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        global buf_size, buf
        l = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % BLOCK_SIZE
        while buf_size < padding + l:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data
        self.cipher(byref(buf), c_char_p(data), padding + l,
                    self.iv_ptr, self.counter // BLOCK_SIZE, self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return buf.raw[padding:padding + l]


class SodiumAeadCrypto(object):
    def __init__(self, cipher_name, key):
        self.__key = key
        self._tlen = 16

        if cipher_name == 'chacha20-ietf-poly1305':
            self._encryptor = libsodium.crypto_aead_chacha20poly1305_ietf_encrypt
            self._decryptor = libsodium.crypto_aead_chacha20poly1305_ietf_decrypt
        else:
            raise Exception('Unknown cipher')

    def encrypt(self, nonce, data, associated):
        global buf, buf_size
        plen = len(data)
        while buf_size < plen + self._tlen:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        self._encryptor(
            byref(buf), byref(cipher_out_len),
            c_char_p(data), c_ulonglong(plen),
            associated_p, associated_l,
            None,
            c_char_p(nonce), c_char_p(self.__key)
        )
        if cipher_out_len.value != plen + self._tlen:
            raise Exception("Encrypt failed")

        return buf.raw[:cipher_out_len.value]

    def decrypt(self, nonce, data, associated):
        global buf, buf_size
        clen = len(data)
        while buf_size < clen:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        r = self._decryptor(
            byref(buf), byref(cipher_out_len),
            None,
            c_char_p(data), c_ulonglong(clen),
            associated_p, associated_l,
            c_char_p(nonce), c_char_p(self.__key)
        )
        if r != 0:
            raise Exception("Decrypt failed")

        if cipher_out_len.value != clen - self._tlen:
            raise Exception("Decrypt failed, length not match")

        return buf.raw[:cipher_out_len.value]
