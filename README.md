#FWLite

A GoAgent / Shadowsocks client. A HTTP proxy server help get through censorship. It detects blocked sites automatically, and apply parent proxy.

Current Version: 4.6

Works on Windows, Linux and Mac(untested).

[Download](http://fwlite.tk/fwlite.zip)

##Features

- Fast and Reliable
- Set IE proxy automatically (windows)
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
- Support Network which require a Proxy
- Support HOSTS
- Support FTP LIST/RETR
- Supported parent proxy
  - HTTP Proxy
  - HTTPS Proxy
  - Socks5 Proxy
  - SNI Proxy
  - [GoAgent]
  - [Shadowsocks]
  - [hxsocks]
- Use GoAgent for HTTP request only
- Remove bad parent proxy automatically
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

    ||360.cn 403

Bad 302 Redirect, counteract ISP conducted MITM hijack(GWBN):

    |http://some.isp.server/ bad302

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk
    ||googlevideo.com goagent

##License

GPLv2

##ICCPR Article 19


1. Everyone shall have the right to hold opinions without interference.

2. Everyone shall have the right to freedom of expression; this right shall include freedom to seek, receive and impart information and ideas of all kinds, regardless of frontiers, either orally, in writing or in print, in the form of art, or through any other media of his choice.

3. The exercise of the rights provided for in paragraph 2 of this article carries with it special duties and responsibilities. It may therefore be subject to certain restrictions, but these shall only be such as are provided by law and are necessary:

    (a) For respect of the rights or reputations of others;

    (b) For the protection of national security or of public order (ordre public), or of public health or morals. 

##Others
[COW]

[GoAgent]

[Shadowsocks]

[pybuild]

[COW]:https://github.com/cyfdecyf/cow
[GoAgent]:https://github.com/goagent/goagent
[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[hxsocks]:https://github.com/v3aqb/hxsocks
[pybuild]:https://github.com/goagent/pybuild
