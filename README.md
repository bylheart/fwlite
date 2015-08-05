#FWLite

A HTTP proxy server designed to circumvent the Great Firewall (GFW). It detects blocked sites automatically, apply parent proxy. And a lot more.

Current Version: 4.9.1

Tested on Windows 7 and openSUSE.

[Download](https://github.com/v3aqb/fwlite/archive/master.zip)

##Quick Start

FW-Lite is Portable Software. You can set your own GoAgent APPID and other parent proxys in the `parents` section of main configuration file `userconf.ini`.

Set your browser's proxy setting to `http://127.0.0.1:8118`, enjoy.

For Windows, run `FW_Lite.exe`

For Linux and Mac, run `FW_Lite.pyw`

requirements under openSUSE:

    zypper install python-repoze.lru python-ipaddr python-gevent
    zypper install python-pyOpenSSL python-pycrypto  # for goagent
    zypper install python-M2Crypto  # or python-cryptography, for shadowsocks
    zypper install python-pyside  # for GUI

##Features

- Set IE proxy automatically (windows)
- URL Search (if your browser doesn't support this well)
- Detect blocked sites
  - autoproxy-gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connection reset
- Multiple work mode
  - gfwlist + auto
  - encrypt-all
  - chnroute
  - global mode
- Support Network which require a Proxy ([issue #39](https://github.com/v3aqb/fwlite/issues/39))
- Support HOSTS
- Support FTP LIST/RETR
- Support websocket protocol
- Simple Adblock
- Supported parent proxy
  - HTTP Proxy
  - HTTPS Proxy (HTTP Proxy over TLS)
  - Socks5 Proxy
  - SNI Proxy
  - [GoAgent]
  - [Shadowsocks]
- Prioritize parent proxies by location and response time(per hostname)
- Use GoAgent for HTTP request only, no worry about certificates
- Redirector
- Support PAC for WPAD
- A simple anti-poison DNS server

Not all features are listed here, and not all of them covered in GUI.

##User Defined Rules(./fgfw-lite/local.txt)

FW-Lite uses [autoproxy rules](http://mydf.github.io/blog/autoproxy/), the differences are:

URL end with keyword:

    .exe|
    .apk|

Redirect

    http://www.baidu.com http://www.google.com

Redirect with Regular Expression

    /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1&ie=gb2312/

Not applying rules for certain sites. For false positeves in gfwlist.

    ||twimg.com auto

forcehttps

    |http://zh.wikipedia.com/ forcehttps

Block certain sites

    ||360.cn 403

Bad 302 Redirect, counteract ISP conducted MITM hijack(GWBN):

    |http://some.isp.server/ bad302

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk
    ||googlevideo.com goagent shadowsocks-us1 shaodwsocks-us2

##License

GPLv2

This Software shall be used for Good, Not for Evil.

##Others
[COW]

[GoAgent]

[Shadowsocks]

[pybuild]

[COW]:https://github.com/cyfdecyf/cow
[GoAgent]:https://github.com/goagent/goagent
[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[pybuild]:https://github.com/goagent/pybuild
