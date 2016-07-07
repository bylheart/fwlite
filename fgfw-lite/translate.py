# -*- coding: utf-8 -*-
import locale
import importlib

try:
    lang = importlib.import_module('lang.%s' % locale.getdefaultlocale()[0])
except Exception:
    lang = importlib.import_module('lang.en_US')


def translate(location, string, dontknowwhat, format):
    try:
        return lang.data[string]
    except KeyError:
        return string
