GoAgent / Shadowsocks client. A HTTP proxy server help get through censorship. It detects blocked sites automatically, and apply parent proxy.

Current Version: 4.6

Works on Windows, Linux and Mac(untested).

[Download](http://fwlite.tk/fwlite.zip)

##Features

- A HTTP Proxy Server fits HTTP1.1 standard
- Configure IE proxy automatically on windows
- URL Search
- Detect blocked sites
  - autoproxy-gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connect reset
- Multiple work mode
  - gfwlist + auto
  - encrypt-all
  - chnroute
  - global mode
- Avoid use of GoAgent for SSL automatically
- Supports Network which require a HTTP Proxy
- Support HOSTS
- Supported parent proxy
  - HTTP Proxy
  - HTTPS Proxy
  - Socks5 Proxy
  - SNI Proxy
  - [GoAgent]
  - [Shadowsocks]
- Supports FTP LIST/RETR
- Redirector
- Automatic Update


##Quick Start

FW-Lite is Portable Software. You can set your own GoAgent APPID and other parent proxys in the main configuration file `userconf.ini`.

Set your browser's proxy setting to `http://127.0.0.1:8118`, enjoy.

For Windows, run `FW_Lite.exe`

For Linux and Mac, run `FW_Lite.pyw`

requirements under openSUSE:

    zypper install python-repoze.lru python-ipaddr python-gevent
    zypper install python-pyOpenSSL python-pycrypto  # for goagent
    zypper install python-M2Crypto  # or python-cryptography, for shadowsocks
    zypper install python-pyside  # for GUI

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

    |http://zh.wikipedia.com/search forcehttps

Block certain sites

    ||dongtaiwang.com 403

Bad 302 Redirect, counteract ISP conducted MITM hijack(GWBN):

    |http://180.89.255.52/ bad302

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk
    ||googlevideo.com goagent

##License

GPLv2

##Others
[COW]

[GoAgent]

[Shadowsocks]

[pybuild]

[COW]:https://github.com/cyfdecyf/cow
[GoAgent]:https://code.google.com/p/goagent/
[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[pybuild]:https://github.com/goagent/pybuild
