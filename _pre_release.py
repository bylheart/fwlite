#!/usr/bin/env python
# coding:utf-8

import sys
import os
import hashlib
import json
import glob
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
os.chdir(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')))

if sys.version_info > (3, 0):
    raw_input = input

if raw_input('update? y/n: ').lower().startswith('y'):
    updatelst = [('https://github.com/goagent/goagent/raw/3.0/local/proxy.py', './goagent/proxy.py'),
                 ('https://github.com/goagent/goagent/raw/3.0/local/proxy.ini', './goagent/proxy.sample.ini'),
                 ('https://github.com/goagent/goagent/raw/3.0/local/proxylib.py', './goagent/proxylib.py'),
                 # ('https://github.com/goagent/goagent/raw/3.0/local/cacert.pem', './goagent/cacert.pem'),
                 # ('https://github.com/goagent/goagent/raw/3.0/local/GeoIP.dat', './goagent/GeoIP.dat'),
                 ('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'),
                 ]
    try:
        import urllib2
    except ImportError:
        import urllib.request as urllib2
    for url, path in updatelst:
        try:
            print('downloading %s' % url)
            r = urllib2.urlopen(url)
        except Exception as e:
            print(repr(e))
        else:
            data = r.read()
            if r.getcode() == 200 and data:
                with open(path, 'wb') as localfile:
                    localfile.write(data)

if raw_input('update ui? y/n: ').lower().startswith('y'):
    for f in glob.glob('./fgfw-lite/ui/*.ui'):
        fname = f.replace('\\', '/').split('/')[-1].split('.')[0]
        os.system('pyside-uic %s -o ./fgfw-lite/ui_%s.py' % (f, fname))


BLOCKSIZE = 8192
flist = ['./fgfw-lite/fgfw-lite.py',
         './fgfw-lite/httputil.py',
         './fgfw-lite/apfilter.py',
         './fgfw-lite/encrypt.py',
         './fgfw-lite/shadowsocks.py',
         './fgfw-lite/dh.py',
         './fgfw-lite/hxsocks.py',
         './fgfw-lite/ctypes_libsodium.py',
         './fgfw-lite/streamcipher.py',
         './fgfw-lite/resolver.py',
         './fgfw-lite/parent_proxy.py',
         './fgfw-lite/connection.py',
         './fgfw-lite/util.py',
         './fgfw-lite/cloud.txt',
         './fgfw-lite/singleton.py',
         './userconf.sample.ini',
         './Python27/python27.zip',
         './README.md',
         './FW_Lite.exe',
         './FW_Lite.pyw',
         './goagent/proxy.py',
         './goagent/proxylib.py',
         './goagent/proxy.sample.ini',
         './goagent/cacert.pem',
         './goagent/GeoIP.dat',
         './release_note.txt',
         ]

for p in glob.glob('./fgfw-lite/ui_*.py'):
    flist.append(p.replace('\\', '/'))

version = configparser.ConfigParser()
version.optionxform = str
version.read('version.ini')
v = {}

for f in flist:
    print('hashing %s' % f)
    hasher = hashlib.sha256()
    with open(f, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    v[f] = hasher.hexdigest()
    version.set('Update', f.replace('./', '').replace('/', '-'), v[f])

with open('./fgfw-lite/update.json', 'wb') as f:
    f.write(json.dumps(v, sort_keys=True, indent=4, separators=(',', ': ')).encode())
with open('version.ini', 'w') as f:
    version.write(f)
raw_input('press Enter to exit...')
