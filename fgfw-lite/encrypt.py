#!/usr/bin/env python
# coding: UTF-8
#
# Copyright (c) 2012 clowwindy
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
#
# Copyright (C) 2013-2016 Jiang Chao <sgzz.cj@gmail.com>
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

import os
import sys
import hashlib
import hmac
import struct

from util import iv_checker

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ctypes_libsodium import Salsa20Crypto

try:
    from hmac import compare_digest
except ImportError:
    def compare_digest(a, b):
        # if a and b are identical, return True
        if isinstance(a, str):
            if len(a) != len(b):
                return False
            result = 0
            for x, y in zip(a, b):
                result |= ord(x) ^ ord(y)
            return result == 0
        else:
            if len(a) != len(b):
                return False
            result = 0
            for x, y in zip(a, b):
                result |= x ^ y
            return result == 0


class BufEmptyError(Exception):
    pass


class TagInvalidError(Exception):
    pass


def random_string(size):
    return os.urandom(size)


def EVP_BytesToKey(password, key_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    m = []
    l = 0
    while l < key_len:
        md5 = hashlib.md5()
        data = password
        if len(m) > 0:
            data = m[len(m) - 1] + password
        md5.update(data)
        m.append(md5.digest())
        l += 16
    ms = b''.join(m)
    return ms[:key_len]


def check(key, method):
    Encryptor(key, method)  # test if the settings if OK


method_supported = {
    # 'id': (key_len, ivlen, is_aead)
    'aes-128-cfb': (16, 16, False),
    'aes-192-cfb': (24, 16, False),
    'aes-256-cfb': (32, 16, False),
    # 'aes-128-ctr': (16, 16, False),
    # 'aes-192-ctr': (24, 16, False),
    # 'aes-256-ctr': (32, 16, False),
    'camellia-128-cfb': (16, 16, False),
    'camellia-192-cfb': (24, 16, False),
    'camellia-256-cfb': (32, 16, False),
    'rc4-md5': (16, 16, False),
    'chacha20-ietf': (32, 12, False),
    # 'bypass': (16, 16, False),  # for testing only

    # TODO: update ctypes_libsodium
    # 'chacha20-ietf-poly1305': (32, 12, True),
}


def is_aead(method):
    return method_supported.get(method)[2]


class bypass(object):
    def __init__(self):
        pass

    def update(self, buf):
        return buf


IV_CHECKER = iv_checker(1048576, 3600)


def get_cipher(key, method, op, iv):
    if method == 'bypass':
        return bypass()
    if method in ('salsa20', 'chacha20', 'chacha20-ietf'):
        return Salsa20Crypto(method, key, iv, op)
    elif method == 'rc4-md5':
        md5 = hashlib.md5()
        md5.update(key)
        md5.update(iv)
        key = md5.digest()
        method = 'rc4'
    cipher = None

    if method.startswith('rc4'):
        pass
    elif method.endswith('ctr'):
        mode = modes.CTR(iv)
    elif method.endswith('cfb'):
        mode = modes.CFB(iv)
    else:
        raise ValueError('operation mode "%s" not supported!' % method.upper())

    if method.startswith('rc4'):
        cipher = Cipher(algorithms.ARC4(key), None, default_backend())
    elif method.startswith('aes'):
        cipher = Cipher(algorithms.AES(key), mode, default_backend())
    elif method.startswith('camellia'):
        cipher = Cipher(algorithms.Camellia(key), mode, default_backend())
    else:
        raise ValueError('crypto algorithm "%s" not supported!' % method.upper())

    return cipher.encryptor() if op else cipher.decryptor()


class Encryptor(object):
    def __init__(self, password, method):
        if method not in method_supported:
            raise ValueError('encryption method not supported')
        if not isinstance(password, bytes):
            password = password.encode('utf8')

        self.method = method
        self._key_len, self._iv_len, is_aead = method_supported.get(method)
        if is_aead:
            raise ValueError('AEAD method is not supported by Encryptor class!')

        self.__key = EVP_BytesToKey(password, self._key_len)

        self._encryptor = None
        self._decryptor = None

    def encrypt(self, buf):
        if not buf:
            raise BufEmptyError
        if not self._encryptor:
            while True:
                _len = len(buf) + self._iv_len - 2
                iv = struct.pack(">H", _len) + random_string(self._iv_len-2)
                try:
                    IV_CHECKER.check(self.__key, iv)
                except ValueError:
                    continue
                break
            self._encryptor = get_cipher(self.__key, self.method, 1, iv)
            return iv + self._encryptor.update(buf)
        return self._encryptor.update(buf)

    def decrypt(self, buf):
        if not buf:
            raise BufEmptyError
        if self._decryptor is None:
            iv = buf[:self._iv_len]
            IV_CHECKER.check(self.__key, iv)
            self._decryptor = get_cipher(self.__key, self.method, 0, iv)
            buf = buf[self._iv_len:]
            if len(buf) == 0:
                return
        return self._decryptor.update(buf)


key_len_to_hash = {
    16: hashlib.md5,
    24: hashlib.sha1,
    32: hashlib.sha256,
}


def AEncryptor(key, method, ctx):
    try:
        return AEncryptor_HMAC(key, method, ctx)
    except ValueError:
        return AEncryptor_AEAD(key, method, ctx)


class AEncryptor_HMAC(object):
    '''
    Provide Authenticated Encryption
    '''
    def __init__(self, key, method, ctx):
        if method not in method_supported:
            raise ValueError('encryption method not supported')

        self._key_len, self._iv_len, is_aead = method_supported.get(method)
        if is_aead:
            raise ValueError('AEAD method is not supported by AEncryptor_HMAC class!')

        self.method = method
        self.__key = key
        self.mac_len = 16
        self.iv_sent = False
        self.hfunc = key_len_to_hash[self._key_len]

        while True:
            iv = random_string(self._iv_len)
            try:
                IV_CHECKER.check(self.__key, iv)
            except ValueError:
                continue
            break
        self.cipher_iv = iv

        encrypt_key = hmac.new(key, self.cipher_iv, hashlib.sha256).digest()[:self._key_len]
        encrypt_auth_key = hmac.new(key, encrypt_key, hashlib.sha256).digest()[:self._key_len]
        self.__enmac = hmac.new(encrypt_auth_key, digestmod=self.hfunc)
        self.__encrypt_seq = 0
        self.cipher = get_cipher(encrypt_key, method, 1, self.cipher_iv)

        self.decipher = None
        self.__demac = None
        self.__decrypt_seq = 0

    def encrypt(self, buf, ad=None):
        if not buf:
            raise BufEmptyError
        if self.iv_sent:
            ct = self.cipher.update(buf)
        else:
            self.iv_sent = True
            ct = self.cipher_iv + self.cipher.update(buf)

        enmac = self.__enmac.copy()
        enmac.update(struct.pack('!Q', self.__encrypt_seq))
        self.__encrypt_seq += 1
        enmac.update(ct)
        if ad:
            enmac.update(ad)
        return ct + enmac.digest()[:self.mac_len]

    def decrypt(self, buf, ad=None):
        if not buf:
            raise BufEmptyError
        if self.decipher is None:
            iv, buf = buf[:self._iv_len], buf[self._iv_len:]
            IV_CHECKER.check(self.__key, iv)
            decrypt_key = hmac.new(self.__key, iv, hashlib.sha256).digest()[:self._key_len]
            decrypt_auth_key = hmac.new(self.__key, decrypt_key, hashlib.sha256).digest()[:self._key_len]
            self.__demac = hmac.new(decrypt_auth_key, digestmod=self.hfunc)
            self.decipher = get_cipher(decrypt_key, self.method, 0, iv)
            del self.__key

        demac = self.__demac.copy()
        demac.update(struct.pack('!Q', self.__decrypt_seq))
        if self.__decrypt_seq == 0:
            demac.update(iv)
        self.__decrypt_seq += 1
        buf, mac = buf[:self.mac_len * -1], buf[self.mac_len * -1:]
        demac.update(buf)
        if ad:
            demac.update(ad)
        rmac = demac.digest()[:self.mac_len]
        pt = self.decipher.update(buf) if buf else b''
        if compare_digest(rmac, mac):
            return pt
        raise TagInvalidError


if sys.version_info[0] == 3:
    def buffer(x):
        return x

try:
    from cryptography.hazmat.primitives.ciphers import aead
    method_supported.update({'aes-128-gcm': (16, 16, True),
                             'aes-192-gcm': (24, 24, True),
                             'aes-256-gcm': (32, 32, True),
                             'chacha20-ietf-poly1305': (32, 12, True),
                             })
except ImportError:
    sys.stderr.write('aead not supported by your python-cryptography')
    aead = None


class AEncryptor_AEAD(object):
    '''
    Provide Authenticated Encryption, compatible with shadowsocks AEAD mode.
    '''
    def __init__(self, key, method, ctx):
        if method not in method_supported:
            raise ValueError('encryption method not supported')

        self._key_len, self._iv_len, is_aead = method_supported.get(method)
        if not is_aead:
            raise ValueError('non-AEAD method is not supported by AEncryptor_AEAD class!')

        self.method = method
        self.algorithm = self.select_algo(method)
        self._ctx = ctx  # SUBKEY_INFO
        self.__key = key

        self._nonce_len = 12
        self._tag_len = 16

        if self._ctx == b"ss-subkey":
            self.encrypt = self.encrypt_ss
            self.__key = EVP_BytesToKey(key, self._key_len)
        else:
            self.encrypt = self._encrypt

        self._encryptor = None
        self._encryptor_nonce = 0

        self._decryptor = None
        self._decryptor_nonce = 0

    def select_algo(self, method):
        if method.startswith('aes'):
            return aead.AESGCM
        return aead.ChaCha20Poly1305

    def key_expand(self, key, iv):
        algo = hashlib.sha1 if self._ctx == b"ss-subkey" else hashlib.sha256
        prk = hmac.new(iv, key, algo).digest()

        hash_len = algo().digest_size
        blocks_needed = self._key_len // hash_len + (1 if self._key_len % hash_len else 0)  # ceil
        okm = b""
        output_block = b""
        for counter in range(blocks_needed):
            output_block = hmac.new(prk,
                                    buffer(output_block + self._ctx + bytearray((counter + 1,))),
                                    algo
                                    ).digest()
            okm += output_block
        return okm[:self._key_len]

    def _encrypt(self, data, ad=None, data_len=None):
        '''
        TCP Chunk (after encryption, *ciphertext*)
        +--------------+------------+
        |    *Data*    |  Data_TAG  |
        +--------------+------------+
        |   Variable   |   Fixed    |
        +--------------+------------+
        for shadowsocks AEAD, this method must be called twice:
        first encrypt Data_Len, then encrypt Data

        '''
        if not data:
            raise BufEmptyError
        nonce = struct.pack('<Q', self._encryptor_nonce) + b'\x00\x00\x00\x00'
        self._encryptor_nonce += 1

        if not self._encryptor:
            _len = len(data) + self._iv_len + self._tag_len - 2
            if self._ctx == b"ss-subkey":
                _len += self._tag_len + data_len

            while True:
                if self._ctx == b"ss-subkey":
                    iv = struct.pack(">H", _len) + random_string(self._iv_len-2)
                else:
                    iv = random_string(self._iv_len)
                try:
                    IV_CHECKER.check(self.__key, iv)
                except ValueError:
                    continue
                break
            _encryptor_skey = self.key_expand(self.__key, iv)
            self._encryptor = self.algorithm(_encryptor_skey)
            ct = self._encryptor.encrypt(nonce, data, ad)
            ct = iv + ct
        else:
            ct = self._encryptor.encrypt(nonce, data, ad)

        return ct

    def encrypt_ss(self, data):
        a = self._encrypt(struct.pack("!H", len(data)), data_len=len(data))
        b = self._encrypt(data)
        return a + b

    def decrypt(self, data, ad=None):
        if not data:
            raise BufEmptyError

        if self._decryptor is None:
            iv, data = data[:self._iv_len], data[self._iv_len:]
            IV_CHECKER.check(self.__key, iv)
            _decryptor_skey = self.key_expand(self.__key, iv)
            self._decryptor = self.algorithm(_decryptor_skey)

        if not data:
            return
        nonce = struct.pack('<Q', self._decryptor_nonce) + b'\x00\x00\x00\x00'
        self._decryptor_nonce += 1
        try:
            return self._decryptor.decrypt(nonce, data, ad)
        except Exception:
            raise TagInvalidError


if __name__ == '__main__':
    # disable ivchecker

    class ivchecker(object):
        def __init__(self, size, timeout):
            pass

        def check(self, key, iv):
            pass

    IV_CHECKER = ivchecker(1, 1)

    print('encrypt and decrypt 20MB data.')
    s = os.urandom(10240)
    import time
    lst = sorted(method_supported.keys())
    for method in lst:
        if is_aead(method):
            continue
        try:
            cipher = Encryptor(b'123456', method)
            t = time.clock()
            for _ in range(1024):
                a = cipher.encrypt(s)
                b = cipher.encrypt(s)
                c = cipher.decrypt(a)
                d = cipher.decrypt(b)
            print('%s %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
    print('test AE HMAC')
    ae1 = AEncryptor_HMAC(b'123456', 'aes-256-cfb', b'ctx')
    ae2 = AEncryptor_HMAC(b'123456', 'aes-256-cfb', b'ctx')
    ct1 = ae1.encrypt(b'abcde')
    ct2 = ae1.encrypt(b'fg')
    print(ae2.decrypt(ct1))
    print(ae2.decrypt(ct2))
    for method in lst:
        if is_aead(method):
            continue
        try:
            cipher1 = AEncryptor_HMAC(b'123456', method, b'ctx')
            cipher2 = AEncryptor_HMAC(b'123456', method, b'ctx')
            t = time.clock()
            for _ in range(1024):
                ct1 = cipher1.encrypt(s)
                ct2 = cipher1.encrypt(s)
                cipher2.decrypt(ct1)
                cipher2.decrypt(ct2)
            print('%s-HMAC %ss' % (method, time.clock() - t))
        except Exception as e:
            print(repr(e))
    print('test AE GCM')
    ae1 = AEncryptor_AEAD(b'123456', 'aes-128-gcm', b'ctx')
    ae2 = AEncryptor_AEAD(b'123456', 'aes-128-gcm', b'ctx')
    ct1 = ae1.encrypt(b'abcde')
    ct2 = ae1.encrypt(b'fg')
    print(ae2.decrypt(ct1))
    print(ae2.decrypt(ct2))

    for method in lst:
        if is_aead(method):
            try:
                cipher1 = AEncryptor_AEAD(b'123456', method, b'ctx')
                cipher2 = AEncryptor_AEAD(b'123456', method, b'ctx')
                t = time.clock()
                for _ in range(1024):
                    ct1 = cipher1.encrypt(s)
                    ct2 = cipher1.encrypt(s)
                    cipher2.decrypt(ct1)
                    cipher2.decrypt(ct2)
                print('%s %ss' % (method, time.clock() - t))
            except Exception as e:
                print(repr(e))
