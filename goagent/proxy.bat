@echo off
@set GEVENT_LOOP=uvent.loop.UVLoop
@set GEVENT_RESOLVER=block
%~dp0../Python27/python27.exe %~dp0proxy.py
