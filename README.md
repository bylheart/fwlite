A HTTP proxy server help get through censorship. It detects blocked sites automatically, and apply parent proxy.

Current Version: 4.4.3

Works on Windows, Linux and Mac(untested).

[Download](http://fwlite.tk/fwlite.zip)

Inspired by [COW]

##Features

- A HTTP Proxy Server fits HTTP1.1 standard
- Sets IE proxy configuration automatically on windows
- Supports Network which require a HTTP Proxy
- URL Search
- Automatic Update
- Multiple Method to detect blocked sites
  - autoproxy-gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connect reset
- Avoid use of fake SSL certs automatically
- Supports FTP LIST/RETR
- Supported parent proxy
  - HTTP Proxy
  - HTTPS Proxy
  - Socks5 Proxy
  - SNI Proxy
  - [GoAgent]
  - [Shadowsocks]
  - [snova] \(PAAS only)

##Quick Start

FW-Lite is Portable Software. You can set your own GoAgent APPID and other parent proxys in the main configuration file `userconf.ini`.

Set your browser's proxy setting to `http://127.0.0.1:8118`, enjoy.

For Windows, run `FW_Lite.exe`

For Linux and Mac, run `FW_Lite.pyw`

requirements under openSUSE:

    zypper install python-repoze.lru python-ipaddr python-gevent
    zypper install python-pyOpenSSL python-pycrypto  # for goagent
    zypper install python-M2Crypto  # or python-cryptography, take your pick. for shadowsocks
    zypper install python-pyside  # for GUI

##Self Defined Rules(./fgfw-lite/local.txt)

FW-Lite uses [autoproxy rules](https://autoproxy.org/zh-CN/Rules), the differences are:

URL end with keyword, used to counteract ISP conducted MITM hijack(GWBN):

    .exe|
    .apk|

Not applying rules for certain sites. For false positeves in gfwlist.

    ||twimg.com auto

forcehttps

    |http://zh.wikipedia.com/search forcehttps

Redirect

    http://www.baidu.com http://www.google.com

Redirect with Regular Expression

    /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1&ie=gb2312/

Block certain sites

    ||dongtaiwang.com 403

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk

##License

GPLv2

[COW]:https://github.com/cyfdecyf/cow
[GoAgent]:https://code.google.com/p/goagent/
[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[snova]:https://code.google.com/p/snova/
[pybuild]:https://github.com/goagent/pybuild
