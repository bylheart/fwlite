#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import threading
import atexit
import base64
import httplib
import json
import urllib2
import signal
import subprocess
import time
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')), 'fgfw-lite'))
from collections import deque
from PySide import QtCore, QtGui
from ui_mainwindow import Ui_MainWindow
from ui_remoteresolver import Ui_remote_resolver
from ui_localrules import Ui_LocalRules
from ui_localrule import Ui_LocalRule
from ui_redirectorrules import Ui_RedirectorRules
from util import SConfigParser
try:
    import pynotify
    pynotify.init('FGFW-Lite Notify')
except ImportError:
    pynotify = None
WORKINGDIR = os.path.dirname(os.path.abspath(__file__).replace('\\', '/'))
os.chdir(WORKINGDIR)

TRAY_ICON = '%s/fgfw-lite/ui/icon.png' % WORKINGDIR
PYTHON = '%s/Python27/python27.exe' % WORKINGDIR if sys.platform.startswith('win') else '/usr/bin/env python2.7'


def setIEproxy(enable, proxy=u'', override=u'<local>'):
    import ctypes
    import _winreg

    access = _winreg.KEY_ALL_ACCESS
    if 'PROGRAMFILES(X86)' in os.environ:
        access |= _winreg.KEY_WOW64_64KEY
    INTERNET_SETTINGS = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER,
                                        r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                        0, access)

    _winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, _winreg.REG_DWORD, enable)
    _winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, _winreg.REG_SZ, proxy)
    _winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyOverride', 0, _winreg.REG_SZ, override)

    ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)


class MainWindow(QtGui.QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        if sys.platform.startswith('win'):
            font = QtGui.QFont()
            font.setFamily("Consolas")
            self.ui.console.setFont(font)
        elif sys.platform.startswith('linux'):
            font = QtGui.QFont()
            font.setFamily("Droid Sans Mono")
            self.ui.console.setFont(font)
        elif sys.platform.startswith('darwin'):
            font = QtGui.QFont()
            font.setFamily("Menlo")
            self.ui.console.setFont(font)
        self.ui.console.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
        self.setWindowIcon(QtGui.QIcon(TRAY_ICON))
        self.center()
        self.consoleText = deque(maxlen=300)
        if not os.path.isfile('./userconf.ini'):
            shutil.copyfile('./userconf.sample.ini', './userconf.ini')
        self.runner = QtCore.QProcess(self)

        self.conf = SConfigParser()
        self.conf.read('userconf.ini')
        listen = self.conf.dget('fgfwproxy', 'listen', '8118')
        self.port = int(listen) if listen.isdigit() else int(listen.split(':')[1])

        self.LocalRules = LocalRules(self)
        self.ui.tabWidget.addTab(self.LocalRules, "")
        self.ui.tabWidget.setTabText(self.ui.tabWidget.indexOf(self.LocalRules), QtGui.QApplication.translate("MainWindow", "LocalRules", None, QtGui.QApplication.UnicodeUTF8))

        self.RedirRules = RedirectorRules(self)
        self.ui.tabWidget.addTab(self.RedirRules, "")
        self.ui.tabWidget.setTabText(self.ui.tabWidget.indexOf(self.RedirRules), QtGui.QApplication.translate("MainWindow", "RedirectorRules", None, QtGui.QApplication.UnicodeUTF8))

        self.trayIcon = None
        self.createActions()
        self.createTrayIcon()
        self.createProcess()
        self.resolve = RemoteResolve()

    def killProcess(self):
        if self.runner.state() == QtCore.QProcess.ProcessState.Running:
            a = urllib2.urlopen('http://127.0.0.1:8118/api/goagent/pid').read()
            if a.isdigit():
                os.kill(int(a), signal.SIGTERM)
            self.runner.kill()
            self.runner.waitForFinished(100)

    def createProcess(self):
        self.killProcess()
        self.runner.readyReadStandardError.connect(self.newStderrInfo)
        self.runner.readyReadStandardOutput.connect(self.newStdoutInfo)
        self.runner.start('%s -B %s/fgfw-lite/fgfw-lite.py' % (PYTHON, WORKINGDIR))

    def newStderrInfo(self):
        self.update_text(str(self.runner.readAllStandardError()).strip())

    def newStdoutInfo(self):
        self.update_text(str(self.runner.readAllStandardOutput()).strip())

    def center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def createActions(self):
        self.showToggleAction = QtGui.QAction(u"显示/隐藏", self, triggered=self.showToggle)
        self.reloadAction = QtGui.QAction(u"重新载入", self, triggered=self.reload)
        self.setIENoneAction = QtGui.QAction(u"直接连接", self, triggered=lambda: setIEproxy(0))
        self.flushDNSAction = QtGui.QAction(u"清空DNS缓存", self, triggered=self.flushDNS)
        self.remoteDNSAction = QtGui.QAction(u"远程DNS解析", self, triggered=self.remoteDNS)
        self.openlocalAction = QtGui.QAction(u"local.txt", self, triggered=self.openlocal)
        self.openconfAction = QtGui.QAction(u"userconf.ini", self, triggered=self.openconf)
        self.quitAction = QtGui.QAction(u"退出", self, triggered=self.on_Quit)

    def createTrayIcon(self):
        if self.trayIcon and self.trayIcon.isVisible():
            self.trayIcon.hide()
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.showToggleAction)
        self.trayIconMenu.addAction(self.reloadAction)

        if sys.platform.startswith('win'):
            self.settingIEproxyMenu = self.trayIconMenu.addMenu(u'设置代理')
            self.setIEProxyMenu()

        advancedMenu = self.trayIconMenu.addMenu(u'高級')
        advancedMenu.addAction(self.flushDNSAction)
        advancedMenu.addAction(self.remoteDNSAction)

        settingMenu = self.trayIconMenu.addMenu(u'设置')
        settingMenu.addAction(self.openconfAction)
        settingMenu.addAction(self.openlocalAction)
        self.trayIconMenu.addSeparator()
        self.trayIconMenu.addAction(self.quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(self)
        self.trayIcon.setToolTip(u'FGFW-Lite')
        self.trayIcon.setContextMenu(self.trayIconMenu)
        self.trayIcon.setIcon(QtGui.QIcon(TRAY_ICON))
        self.trayIcon.activated.connect(self.on_trayActive)
        self.trayIcon.show()

    def setIEProxyMenu(self):
        self.settingIEproxyMenu.clear()

        profile = [int(x) for x in self.conf.dget('fgfwproxy', 'profile', '134')]
        for i, p in enumerate(profile):
            d = {1: u'智能代理%d',
                 2: u'全局加密%d',
                 3: u'国内直连%d',
                 4: u'全局代理%d',
                 }
            title = d[p] % (self.port + i) if p in d else (u'127.0.0.1:%d profile%d' % ((self.port + i), p))
            self.settingIEproxyMenu.addAction(QtGui.QAction(title, self, triggered=lambda: setIEproxy(1, u'127.0.0.1:%d' % (self.port + i))))
        self.settingIEproxyMenu.addAction(self.setIENoneAction)
        if self.conf.dgetbool('FGFW_Lite', 'setIEProxy', True):
            setIEproxy(1, u'127.0.0.1:%d' % self.port)

    def flushDNS(self):
        if sys.platform.startswith('win'):
            os.system('ipconfig.exe /flushdns')
        elif sys.platform.startswith('darwin'):
            os.system('dscacheutil -flushcache')
        elif sys.platform.startswith('linux'):
            self.showMessage(u'for Linux system, you need to run "sudo /etc/init.d/nscd restart"')
        else:
            self.showMessage(u'OS not recognised')

    def remoteDNS(self):
        self.resolve.show()

    def showMessage(self, msg, timeout=None):
        if pynotify:
            notification = pynotify.Notification('FGFW-Lite Notify', msg)
            notification.set_hint('x', 200)
            notification.set_hint('y', 400)
            if timeout:
                notification.set_timeout(timeout)
            notification.show()
        else:
            self.trayIcon.showMessage(u'FGFW-Lite', msg)

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.trayIcon.isVisible():
            self.hide()
        event.ignore()

    def on_trayActive(self, reason):
        if reason is self.trayIcon.Trigger:
            self.showToggle()

    def openlocal(self):
        self.openfile('./fgfw-lite/local.txt')

    def openconf(self):
        self.openfile('userconf.ini')

    def openfile(self, path):
        if sys.platform.startswith('win'):
            cmd = 'start'
        elif sys.platform.startswith('linux'):
            cmd = 'xdg-open'
        elif sys.platform.startswith('darwin'):
            cmd = 'open'
        else:
            return self.showMessage('OS not recognised')
        subprocess.Popen('%s %s' % (cmd, path), shell=True)
        self.showMessage(u'新的设置将在重新载入后生效')

    def on_Quit(self):
        QtGui.qApp.quit()

    def update_text(self, text):
        freload = False
        lines = text.splitlines()
        self.consoleText.extend(lines)
        for line in lines:
            if 'Update Completed' in line:
                self.showMessage(u'已升级到最新版，重新载入中...')
                freload = True
        self.ui.console.setPlainText(u'\n'.join(self.consoleText))
        self.ui.console.moveCursor(QtGui.QTextCursor.End)
        if freload:
            self.reload(clear=False)

    def showToggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.ui.tabWidget.setCurrentIndex(0)
            self.show()
            if self.isMinimized():
                self.showNormal()
            self.activateWindow()

    def reload(self, clear=True):
        if clear:
            self.ui.console.clear()
            self.consoleText.clear()
        if sys.platform.startswith('win'):
            self.setIEProxyMenu()
        self.createProcess()


class LocalRules(QtGui.QWidget):
    ref = QtCore.Signal()

    def __init__(self, parent=None):
        super(LocalRules, self).__init__(parent)
        self.ui = Ui_LocalRules()
        self.ui.setupUi(self)
        self.ui.AddLocalRuleButton.clicked.connect(self.addLocalRule)
        self.ref.connect(self.refresh)
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.port = parent.port
        self.list = []

    def refresh(self):
        if self.ui.LocalRulesLayout.count():
            self.clearLayout(self.ui.LocalRulesLayout)
        data = json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/localrule' % self.port, timeout=1).read())
        for rid, rule, exp in data:
            w = LocalRule(rid, rule, exp, self.port, self.ref)
            self.ui.LocalRulesLayout.addWidget(w)
        self.ui.LocalRulesLayout.addItem(QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding))
        if not self.timer.isActive():
            self.timer.start(1000)

    def clearLayout(self, layout):
        if layout is not None:
            try:
                while layout.count():
                    item = layout.takeAt(0)
                    widget = item.widget()
                    if widget is not None:
                        widget.deleteLater()
                    else:
                        self.clearLayout(item.layout())
            except:
                pass

    def addLocalRule(self):
        exp = int(self.ui.ExpireEdit.text()) if self.ui.ExpireEdit.text().isdigit() and int(self.ui.ExpireEdit.text()) > 0 else None
        data = json.dumps((self.ui.LocalRuleEdit.text(), exp))
        urllib2.urlopen('http://127.0.0.1:%d/api/localrule' % self.port, data, timeout=1)
        self.refresh()


class LocalRule(QtGui.QWidget):
    def __init__(self, rid, rule, exp, port, ref, parent=None):
        super(LocalRule, self).__init__(parent)
        self.ui = Ui_LocalRule()
        self.ui.setupUi(self)
        self.ui.delButton.clicked.connect(self.delrule)
        self.port = port
        self.rule = rule
        self.rid = rid
        self.exp = exp
        self.ref = ref
        exp = exp - time.time() if exp else None
        text = '%s%s' % (self.rule, (' expire %.1fs' % exp if exp else ''))
        self.ui.lineEdit.setText(text)

    def delrule(self):
        conn = httplib.HTTPConnection('127.0.0.1', self.port, timeout=1)
        conn.request('DELETE', '/api/localrule/%d?rule=%s' % (self.rid, base64.urlsafe_b64encode(self.rule)))
        resp = conn.getresponse()
        content = resp.read()
        print(content)
        self.ref.emit()


class RedirectorRules(QtGui.QWidget):
    ref = QtCore.Signal()

    def __init__(self, parent=None):
        super(RedirectorRules, self).__init__(parent)
        self.ui = Ui_RedirectorRules()
        self.ui.setupUi(self)
        self.ui.AddRedirectorRuleButton.clicked.connect(self.addRedirRule)
        self.ref.connect(self.refresh)
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.port = parent.port
        self.list = []

    def refresh(self):
        if self.ui.RedirectorRulesLayout.count():
            self.clearLayout(self.ui.RedirectorRulesLayout)
        data = json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/redirector' % self.port, timeout=1).read())
        for rid, rule, exp in data:
            w = RedirRule(rid, rule, exp, self.port, self.ref)
            self.ui.RedirectorRulesLayout.addWidget(w)
        self.ui.RedirectorRulesLayout.addItem(QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding))
        if not self.timer.isActive():
            self.timer.start(1000)

    def clearLayout(self, layout):
        if layout is not None:
            try:
                while layout.count():
                    item = layout.takeAt(0)
                    widget = item.widget()
                    if widget is not None:
                        widget.deleteLater()
                    else:
                        self.clearLayout(item.layout())
            except:
                pass

    def addRedirRule(self):
        data = json.dumps((self.ui.RuleEdit.text(), self.ui.DestEdit.text()))
        urllib2.urlopen('http://127.0.0.1:%d/api/redirector' % self.port, data, timeout=1)
        self.refresh()


class RedirRule(QtGui.QWidget):
    def __init__(self, rid, rule, dest, port, ref, parent=None):
        super(RedirRule, self).__init__(parent)
        self.ui = Ui_LocalRule()
        self.ui.setupUi(self)
        self.ui.delButton.clicked.connect(self.delrule)
        self.port = port
        self.rule = rule
        self.rid = rid
        self.ref = ref
        text = '%s %s' % (self.rule, dest)
        self.ui.lineEdit.setText(text)

    def delrule(self):
        conn = httplib.HTTPConnection('127.0.0.1', self.port, timeout=1)
        conn.request('DELETE', '/api/redirector/%d?rule=%s' % (self.rid, base64.urlsafe_b64encode(self.rule)))
        resp = conn.getresponse()
        content = resp.read()
        print(content)
        self.ref.emit()


class RemoteResolve(QtGui.QWidget):
    trigger = QtCore.Signal(str)

    def __init__(self, parent=None):
        super(RemoteResolve, self).__init__(parent)
        self.ui = Ui_remote_resolver()
        self.ui.setupUi(self)
        self.ui.goButton.clicked.connect(self.do_resolve)
        self.trigger.connect(self.ui.resultTextEdit.setPlainText)

    def do_resolve(self):
        self.ui.resultTextEdit.setPlainText('resolving...')
        threading.Thread(target=self._do_resolve, args=(self.ui.hostLineEdit.text(), self.ui.serverComboBox.currentText())).start()

    def _do_resolve(self, host, server):
        try:
            result = json.loads(urllib2.urlopen('http://155.254.32.50/dns?q=%s&server=%s' % (base64.urlsafe_b64encode(host).strip('='), server), timeout=1).read())
        except Exception as e:
            result = [repr(e)]
        self.trigger.emit('\n'.join(result))

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.isVisible():
            self.hide()
        self.ui.resultTextEdit.clear()
        event.ignore()


@atexit.register
def atexit_do():
    if sys.platform.startswith('win'):
        setIEproxy(0)
    win.killProcess()


if __name__ == "__main__":
    if os.name == 'nt':
        import ctypes
        myappid = 'v3aqb.fgfw-lite'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    app = QtGui.QApplication('')
    win = MainWindow()
    sys.exit(app.exec_())
