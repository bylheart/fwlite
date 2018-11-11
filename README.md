# FWLite

A anti-censorship HTTP proxy with builtin shadowsocks support.

Current Version: 4.22

Tested on Windows 7 and Windows 10.

[Download](https://github.com/v3aqb/fwlite/archive/master.zip)

## Known Issues

- Incompatible with slow DNS server(ie. Pcap_DNSProxy) (issue 62)

## For Linux and Mac:

Check [fwlite-cli] and [fwlite-gui].

## Quick Start

#### Set parent proxy

Add your own parent proxy in the `parents` section of main configuration file `userconf.ini`.

It looks like this:

    [parents]
    shadowsocks = ss://aes-256-cfb:password@127.0.0.1:8388
    shadowsocks_aead = ss://aes-256-gcm:password@127.0.0.1:8388

or this:

    [parents]
    proxy1 = http://user:pass@127.0.0.1:8087
    proxy2 = socks5://127.0.0.1:1080

    # connect to 'http://server:8087' via 'socks5://127.0.0.1:1080'
    proxy3 = http://server:8087|socks5://127.0.0.1:1080

#### Set browser

Set your browser's proxy setting to `http://127.0.0.1:8118`.

On Windows, this should be done automatically.

#### Start

run `FWLite.exe`

## Features

- Set IE proxy automatically (windows)
- Detect blocked sites automatically
  - autoproxy-gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connection reset
- Multiple work profile
- Support Network which require a Proxy ([issue #39](https://github.com/v3aqb/fwlite/issues/39))
- Support websocket protocol
- Supported parent proxy
  - HTTP Proxy
  - Socks5 Proxy
  - [Shadowsocks] by @clowwindy (with AEAD support)
- Prioritize parent proxies by response time
- Redirector
- Simple PAC for WPAD

Not all features are listed here, and only few of them are covered in GUI.

## User Defined Rules(./fgfw-lite/local.txt)

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

Close connection

    ||360.cn reset

Bad 302 Redirect, counteract ISP conducted MITM hijack(GWBN):

    |http://some.isp.server/ bad302

Assign a parent proxy for certain sites

    ||bbc.co.uk shadowsocks-uk
    ||googlevideo.com shadowsocks-us1 shaodwsocks-us2

## License

GPLv2

## More info

[翻墙路由器的原理与实现]

[Shadowsocks]

[pybuild]

[gfwlist]

[Shadowsocks]:https://github.com/clowwindy/shadowsocks
[pybuild]:https://github.com/goagent/pybuild
[gfwlist]:https://github.com/gfwlist/gfwlist
[翻墙路由器的原理与实现]:https://docs.google.com/document/d/1mmMiMYbviMxJ-DhTyIGdK7OOg581LSD1CZV4XY1OMG8/pub
[fwlite-cli]:https://github.com/v3aqb/fwlite-cli
[fwlite-gui]:https://github.com/v3aqb/fwlite-gui
