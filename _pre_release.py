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
    updatelst = [('https://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt', './fgfw-lite/gfwlist.txt'),
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

    for path in glob.glob('./fgfw-lite/ui_*.py'):
        with open(path, 'r') as f:
            data = f.read()
        with open(path, 'w') as f:
            f.write('# -*- coding: utf-8 -*-\nimport translate\ntr = translate.translate\n')
            f.write(data.replace('QtGui.QApplication.translate', 'tr'))


BLOCKSIZE = 8192
flist = ['./fgfw-lite/fgfw-lite.py',
         './fgfw-lite/httputil.py',
         './fgfw-lite/apfilter.py',
         './fgfw-lite/config.py',
         './fgfw-lite/encrypt.py',
         './fgfw-lite/basesocket.py',
         './fgfw-lite/dnsserver.py',
         './fgfw-lite/sssocket.py',
         './fgfw-lite/hxsocks.py',
         './fgfw-lite/ctypes_libsodium.py',
         './fgfw-lite/streamcipher.py',
         './fgfw-lite/redirector.py',
         './fgfw-lite/resolver.py',
         './fgfw-lite/translate.py',
         './fgfw-lite/parent_proxy.py',
         './fgfw-lite/get_proxy.py',
         './fgfw-lite/connection.py',
         './fgfw-lite/util.py',
         './fgfw-lite/singleton.py',
         './fgfw-lite/cloud.txt',
         './fgfw-lite/GeoLite2-Country.mmdb',
         './userconf.sample.ini',
         './Python27/python27.zip',
         './README.md',
         './FWLite.exe',
         './FWLite.pyw',
         './release_note.txt',
         ]

for p in glob.glob('./fgfw-lite/ui_*.py'):
    flist.append(p.replace('\\', '/'))

for p in glob.glob('./fgfw-lite/lang/*.py'):
    flist.append(p.replace('\\', '/'))

for p in glob.glob('./Python27/*.egg'):
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
