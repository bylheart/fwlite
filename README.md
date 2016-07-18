#FWLite

A anti-censorship HTTP proxy with builtin shadowsocks support.

Current Version: 4.15.3

Tested on Windows 7 and Windows 10.

[Download](https://github.com/v3aqb/fwlite/archive/master.zip)

##Quick Start

####Set parent proxy
Add your own parent proxy in the `parents` section of main configuration file `userconf.ini`.

It looks like this:

    [parents]
    shadowsocks = ss://aes-256-cfb:password@127.0.0.1:8388
    shadowsocks_with_OTA = ss://aes-256-cfb-auth:password@127.0.0.1:8388

or this:

    [parents]
    proxy1 = http://127.0.0.1:8086
    proxy2 = http://user:pass@127.0.0.1:8087
    proxy3 = socks5://127.0.0.1:1080

####Set browser
Set your browser's proxy setting to `http://127.0.0.1:8118`.

On Windows, this should be done automatically.

####Start
For Windows, run `FWLite.exe`

For Linux and Mac, run `FWLite.pyw`

####Instruction under openSUSE

    sudo zypper install python-virtualenv

	# create virtualenv
	virtualenv env

	# install requirements
	sudo zypper install gcc python-devel libffi-devel
	./env/bin/python -m pip install repoze.lru ipaddr dnslib chardet geoip2
	./env/bin/python -m pip install gevent cryptography

	# install requirements for GUI. It's gonna take a while.
	sudo zypper in libqt4-devel
    ./env/bin/python -m pip install pyside

	# run fwlite GUI
	./env/bin/python path_to/FWLite.pyw

##Features

- Set IE proxy automatically (windows)
- URL Search (if your browser doesn't support this well)
- Detect blocked sites automatically
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
  - [Shadowsocks] by @clowwindy (with OTA support)
  - SNI Proxy (**DANGER, STAY AWAY FROM THIS**)
- Prioritize parent proxies by location and response time
- Redirector(some hidden function here)
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

Not applying rules for certain sites. For false positives in gfwlist.

    ||twimg.com auto

forcehttps

    |http://zh.wikipedia.com/ forcehttps

Block certain sites

    ||360.cn 403

Bad 302 Redirect, counteract ISP conducted MITM hijack(GWBN):

    |http://some.isp.server/ bad302

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk
    ||googlevideo.com shadowsocks-us1 shaodwsocks-us2

##License

GPLv2

##Thanks
[翻墙路由器的原理与实现]

[COW]

[GoAgent]

[Shadowsocks]

[fqrouter]

[pybuild]

[gfwlist]

[hxsocks]

[COW]:https://github.com/cyfdecyf/cow
[GoAgent]:https://github.com/goagent/goagent
[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[fqrouter]:https://github.com/fqrouter/fqrouter
[pybuild]:https://github.com/goagent/pybuild
[hxsocks]:https://github.com/v3aqb/hxsocks
[gfwlist]:https://github.com/gfwlist/gfwlist
[翻墙路由器的原理与实现]:https://docs.google.com/document/d/1mmMiMYbviMxJ-DhTyIGdK7OOg581LSD1CZV4XY1OMG8/pub
