# -*- coding: utf-8 -*-
import locale
import importlib


class translate(object):
    try:
        lang = importlib.import_module('lang.%s' % locale.getdefaultlocale()[0])
    except:
        lang = importlib.import_module('lang.en_US')

    @classmethod
    def translate(cls, location, string, dontknowwhat, format):
        try:
            return cls.lang.data[string]
        except:
            return string
