#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import sys
import glob
sys.dont_write_bytecode = True
WORKINGDIR = os.path.dirname(os.path.abspath(__file__).replace('\\', '/'))
os.chdir(WORKINGDIR)
sys.path += glob.glob('%s/Python27/*.egg' % WORKINGDIR)
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')), 'fgfw-lite'))
import copy
import datetime
import shutil
import threading
import atexit
import base64
import operator
import json
import subprocess
from collections import deque
from PySide import QtCore, QtGui
from ui_mainwindow import Ui_MainWindow
from ui_remoteresolver import Ui_remote_resolver
from ui_localrules import Ui_LocalRules
from ui_localrule import Ui_LocalRule
from ui_redirectorrules import Ui_RedirectorRules
from ui_settings import Ui_Settings
from util import SConfigParser, parse_hostport
from resolver import tcp_dns_record
from parent_proxy import ParentProxy
import translate
tr = translate.translate
try:
    import httplib
    import urllib2
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote
except ImportError:
    import http.client as httplib
    import urllib.request as urllib2
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
try:
    from singleton import SingleInstance
    SINGLEINSTANCE = SingleInstance()
except ImportError as e:
    print(repr(e))
try:
    import pynotify
    pynotify.init('FWLite Notify')
except ImportError:
    pynotify = None

TRAY_ICON = './fgfw-lite/ui/icon.png'

if not os.path.isfile('./userconf.ini'):
    shutil.copyfile('./userconf.sample.ini', './userconf.ini')


def setIEproxy(enable, proxy=u'', override=u'<local>'):
    import ctypes
    try:
        import _winreg as winreg
    except:
        import winreg
    if enable == 0:
        proxy = u''
    INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                       r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                                       0, winreg.KEY_WRITE)

    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyEnable', 0, winreg.REG_DWORD, enable)
    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyServer', 0, winreg.REG_SZ, proxy)
    winreg.SetValueEx(INTERNET_SETTINGS, 'ProxyOverride', 0, winreg.REG_SZ, override)

    ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)


def setFont(item):
    if sys.platform.startswith('win'):
        font = QtGui.QFont()
        font.setFamily("Consolas")
        item.setFont(font)
    elif sys.platform.startswith('linux'):
        font = QtGui.QFont()
        font.setFamily("Droid Sans Mono")
        item.setFont(font)
    elif sys.platform.startswith('darwin'):
        font = QtGui.QFont()
        font.setFamily("Menlo")
        item.setFont(font)


class MainWindow(QtGui.QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        setFont(self.ui.console)
        self.ui.console.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
        self.setWindowIcon(QtGui.QIcon(TRAY_ICON))
        self.center()
        self.consoleText = deque(maxlen=300)

        self.runner = QtCore.QProcess(self)

        self.conf = SConfigParser()
        self.conf.read('userconf.ini')
        listen = self.conf.dget('fgfwproxy', 'listen', '8118')
        self.port = int(listen) if listen.isdigit() else int(listen.split(':')[1])

        self.LocalRules = LocalRules(self)
        self.ui.tabWidget.addTab(self.LocalRules, tr("MainWindow", "user_rules", None, QtGui.QApplication.UnicodeUTF8))

        self.RedirRules = RedirectorRules(self)
        self.ui.tabWidget.addTab(self.RedirRules, tr("MainWindow", "redir_rules", None, QtGui.QApplication.UnicodeUTF8))

        self.Settings = Settings(self)
        self.ui.tabWidget.addTab(self.Settings, tr("MainWindow", "settings", None, QtGui.QApplication.UnicodeUTF8))

        self.resolve = RemoteResolve(self)

        self.trayIcon = None
        self.createActions()
        self.createTrayIcon()
        self.createProcess()

    def killProcess(self):
        if self.runner.state() == QtCore.QProcess.ProcessState.Running:
            self.runner.kill()
            self.runner.waitForFinished(100)

    def createProcess(self):
        self.killProcess()
        self.runner.readyReadStandardError.connect(self.newStderrInfo)
        self.runner.readyReadStandardOutput.connect(self.newStdoutInfo)
        python = ('"./Python27/python27.exe"') if sys.platform.startswith('win') else '/usr/bin/env python'
        cmd = '%s -B ./fgfw-lite/fgfw-lite.py -GUI' % python
        self.runner.start(cmd)

    def newStderrInfo(self):
        freload = False
        lines = str(self.runner.readAllStandardError()).strip().splitlines()
        for line in copy.copy(lines):
            if 'Update Completed' in line:
                freload = True
            elif 'dnslib_resolve_over_' in line:
                lines.remove(line)
            elif 'extend_iplist start' in line:
                lines.remove(line)
            elif 'host to iplist' in line:
                lines.remove(line)
            elif '<DNS Question:' in line:
                lines.remove(line)
        self.consoleText.extend(lines)
        self.ui.console.setPlainText(u'\n'.join(self.consoleText))
        self.ui.console.moveCursor(QtGui.QTextCursor.End)
        if freload:
            self.reload(clear=False)

    def newStdoutInfo(self):
        self.LocalRules.ref.emit()
        self.RedirRules.ref.emit()
        self.Settings.ref.emit()

    def center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def createActions(self):
        self.showToggleAction = QtGui.QAction(tr("MainWindow", "show_toggle", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.showToggle)
        self.reloadAction = QtGui.QAction(tr("MainWindow", "reload", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.reload)
        self.setIENoneAction = QtGui.QAction(tr("MainWindow", "direct_access", None, QtGui.QApplication.UnicodeUTF8), self, triggered=lambda: setIEproxy(0))
        self.flushDNSAction = QtGui.QAction(tr("MainWindow", "clear_dns_cache", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.flushDNS)
        self.remoteDNSAction = QtGui.QAction(tr("MainWindow", "remote_dns_resolve", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.remoteDNS)
        self.settingDNSAction = QtGui.QAction(tr("MainWindow", "settings", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.openSetting)
        self.quitAction = QtGui.QAction(tr("MainWindow", "exit", None, QtGui.QApplication.UnicodeUTF8), self, triggered=self.on_Quit)

    def createTrayIcon(self):
        if self.trayIcon and self.trayIcon.isVisible():
            self.trayIcon.hide()
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.showToggleAction)
        self.trayIconMenu.addAction(self.reloadAction)

        if sys.platform.startswith('win'):
            self.settingIEproxyMenu = self.trayIconMenu.addMenu(tr("MainWindow", "set_proxy", None, QtGui.QApplication.UnicodeUTF8))
            self.setIEProxyMenu()

        advancedMenu = self.trayIconMenu.addMenu(tr("MainWindow", "advanced", None, QtGui.QApplication.UnicodeUTF8))
        advancedMenu.addAction(self.flushDNSAction)
        advancedMenu.addAction(self.remoteDNSAction)

        self.trayIconMenu.addAction(self.settingDNSAction)
        self.trayIconMenu.addSeparator()
        self.trayIconMenu.addAction(self.quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(self)
        self.trayIcon.setToolTip(u'FWLite')
        self.trayIcon.setContextMenu(self.trayIconMenu)
        self.trayIcon.setIcon(QtGui.QIcon(TRAY_ICON))
        self.trayIcon.activated.connect(self.on_trayActive)
        self.trayIcon.show()

    def setIEProxyMenu(self):
        self.settingIEproxyMenu.clear()

        profile = [int(x) for x in self.conf.dget('fgfwproxy', 'profile', '13')]
        for i, p in enumerate(profile):
            d = {0: tr("MainWindow", "direct_access", None, QtGui.QApplication.UnicodeUTF8),
                 1: tr("MainWindow", "auto_routing", None, QtGui.QApplication.UnicodeUTF8),
                 2: tr("MainWindow", "encrypt_all", None, QtGui.QApplication.UnicodeUTF8),
                 3: tr("MainWindow", "chnroute", None, QtGui.QApplication.UnicodeUTF8),
                 4: tr("MainWindow", "global_mode", None, QtGui.QApplication.UnicodeUTF8),
                 }
            title = d[p] + str(self.port + i) if p in d else (u'127.0.0.1:%d profile%d' % ((self.port + i), p))
            if i < 6:
                self.settingIEproxyMenu.addAction(QtGui.QAction(title, self, triggered=getattr(self, 'set_ie_p%d' % i)))
        self.settingIEproxyMenu.addAction(self.setIENoneAction)
        if self.conf.dgetbool('FGFW_Lite', 'setIEProxy', True):
            setIEproxy(1, u'127.0.0.1:%d' % self.port)

    def set_ie_p0(self):
        setIEproxy(1, u'127.0.0.1:%d' % self.port)

    def set_ie_p1(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.port + 1))

    def set_ie_p2(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.port + 2))

    def set_ie_p3(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.port + 3))

    def set_ie_p4(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.port + 4))

    def set_ie_p5(self):
        setIEproxy(1, u'127.0.0.1:%d' % (self.port + 5))

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
            notification = pynotify.Notification('FWLite Notify', msg)
            notification.set_hint('x', 200)
            notification.set_hint('y', 400)
            if timeout:
                notification.set_timeout(timeout)
            notification.show()
        else:
            self.trayIcon.showMessage(u'FWLite', msg)

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.trayIcon.isVisible():
            self.hide()
        event.ignore()

    def on_trayActive(self, reason):
        if reason is self.trayIcon.Trigger:
            self.showToggle()

    def on_Quit(self):
        QtGui.qApp.quit()

    def openSetting(self):
        self.ui.tabWidget.setCurrentIndex(3)
        self.show()
        if self.isMinimized():
            self.showNormal()
        self.activateWindow()

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
        self.spacer = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.ui.LocalRulesLayout.addItem(self.spacer)
        self.ref.connect(self.refresh)
        self.port = parent.port
        self.icon = parent
        self.widgetlist = []

    def refresh(self):
        try:
            data = json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/localrule' % self.port, timeout=1).read().decode())
            lst = []
            self.ui.LocalRulesLayout.removeItem(self.spacer)
            for rule, exp in data:
                if self.widgetlist:
                    w = self.widgetlist.pop(0)
                    w.updaterule(rule, exp)
                    w.setVisible(True)
                else:
                    w = LocalRule(rule, exp, self.port)
                    self.ui.LocalRulesLayout.addWidget(w)
                lst.append(w)
            for w in self.widgetlist:
                w.setVisible(False)
            self.ui.LocalRulesLayout.addItem(self.spacer)
            self.widgetlist = lst
        except:
            pass

    def addLocalRule(self):
        exp = int(self.ui.ExpireEdit.text()) if self.ui.ExpireEdit.text().isdigit() and int(self.ui.ExpireEdit.text()) > 0 else None
        rule = self.ui.LocalRuleEdit.text()
        data = json.dumps((rule, exp)).encode()
        try:
            urllib2.urlopen('http://127.0.0.1:%d/api/localrule' % self.port, data, timeout=1)
        except:
            self.icon.showMessage('add localrule %s failed!' % rule)
        else:
            self.ui.LocalRuleEdit.clear()
            self.ui.ExpireEdit.clear()


class LocalRule(QtGui.QWidget):
    def __init__(self, rule, exp, port, parent=None):
        super(LocalRule, self).__init__(parent)
        self.ui = Ui_LocalRule()
        self.ui.setupUi(self)
        self.ui.delButton.clicked.connect(self.delrule)
        self.ui.copyButton.clicked.connect(self.rulecopy)
        self.port = port
        self.rule = rule
        self.updaterule(rule, exp)

    def rulecopy(self):
        cb = QtGui.QApplication.clipboard()
        cb.clear(mode=cb.Clipboard)
        cb.setText(self.rule, mode=cb.Clipboard)

    def delrule(self):
        conn = httplib.HTTPConnection('127.0.0.1', self.port, timeout=1)
        conn.request('DELETE', '/api/localrule/%s' % base64.urlsafe_b64encode(self.rule.encode()))
        resp = conn.getresponse()
        content = resp.read()
        print(content)

    def updaterule(self, rule, exp):
        self.rule = rule
        self.exp = exp
        text = '%s%s' % (self.rule, (' expire in %.1fs' % exp if exp else ''))
        self.ui.lineEdit.setText(text)


class RedirectorRules(QtGui.QWidget):
    ref = QtCore.Signal()

    def __init__(self, parent=None):
        super(RedirectorRules, self).__init__(parent)
        self.ui = Ui_RedirectorRules()
        self.ui.setupUi(self)
        self.ui.AddRedirectorRuleButton.clicked.connect(self.addRedirRule)
        self.spacer = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.ui.RedirectorRulesLayout.addItem(self.spacer)
        self.ref.connect(self.refresh)
        self.port = parent.port
        self.icon = parent
        self.widgetlist = []

    def refresh(self):
        try:
            data = json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/redirector' % self.port, timeout=1).read().decode())
            lst = []
            self.ui.RedirectorRulesLayout.removeItem(self.spacer)
            for rid, rule, exp in data:
                if self.widgetlist:
                    w = self.widgetlist.pop(0)
                    w.updaterule(rid, rule, exp)
                    w.setVisible(True)
                else:
                    w = RedirRule(rid, rule, exp, self.port)
                    self.ui.RedirectorRulesLayout.addWidget(w)
                lst.append(w)
            for w in self.widgetlist:
                w.setVisible(False)
            self.ui.RedirectorRulesLayout.addItem(self.spacer)
            self.widgetlist = lst
        except:
            pass

    def addRedirRule(self):
        rule = self.ui.RuleEdit.text()
        dest = self.ui.DestEdit.text()
        data = json.dumps((rule, dest)).encode()
        try:
            urllib2.urlopen('http://127.0.0.1:%d/api/redirector' % self.port, data, timeout=1)
        except:
            self.icon.showMessage('add redirrule %s %s failed!' % (rule, dest))
        else:
            self.ui.RuleEdit.clear()
            self.ui.DestEdit.clear()


class RedirRule(QtGui.QWidget):
    def __init__(self, rid, rule, dest, port, parent=None):
        super(RedirRule, self).__init__(parent)
        self.ui = Ui_LocalRule()
        self.ui.setupUi(self)
        self.ui.delButton.clicked.connect(self.delrule)
        self.ui.copyButton.hide()
        self.port = port
        self.updaterule(rid, rule, dest)

    def delrule(self):
        conn = httplib.HTTPConnection('127.0.0.1', self.port, timeout=1)
        conn.request('DELETE', '/api/redirector/%d?rule=%s' % (self.rid, base64.urlsafe_b64encode(self.rule.encode())))
        resp = conn.getresponse()
        content = resp.read()
        print(content)

    def updaterule(self, rid, rule, dest):
        self.rid = rid
        self.rule = rule
        text = '%s %s' % (self.rule, dest)
        self.ui.lineEdit.setText(text)


class RemoteResolve(QtGui.QWidget):
    trigger = QtCore.Signal(str)

    def __init__(self, parent=None):
        super(RemoteResolve, self).__init__()
        self.port = parent.port
        self.ui = Ui_remote_resolver()
        self.ui.setupUi(self)
        self.ui.goButton.clicked.connect(self.do_resolve)
        self.trigger.connect(self.ui.resultTextEdit.setPlainText)

    def do_resolve(self):
        self.ui.resultTextEdit.setPlainText(tr("MainWindow", "resolving_notice", None, QtGui.QApplication.UnicodeUTF8))
        threading.Thread(target=self._do_resolve, args=(self.ui.hostLineEdit.text(), self.ui.serverlineEdit.text())).start()

    def _do_resolve(self, host, server):
        try:
            # result = json.loads(urllib2.urlopen('http://155.254.32.50/dns?q=%s&server=%s' % (base64.urlsafe_b64encode(host.encode()).decode().strip('='), server), timeout=1).read().decode())
            proxy = ParentProxy('foo', 'http://127.0.0.1:%d' % self.port)
            server = parse_hostport(server, 53)
            record = tcp_dns_record(host, 'ANY', server, proxy)
            if record is None:
                return []
            while len(record.rr) == 1 and record.rr[0].rtype == 5:
                record = tcp_dns_record(str(record.rr[0].rdata), proxy, 'ANY', server)
            result = [str(x.rdata) for x in record.rr if x.rtype in (1, 28)]
        except Exception as e:
            result = [repr(e)]
        self.trigger.emit('\n'.join(result))

    def closeEvent(self, event):
        # hide mainwindow when close
        if self.isVisible():
            self.hide()
        self.ui.resultTextEdit.clear()
        event.ignore()


class Settings(QtGui.QWidget):
    ref = QtCore.Signal()

    def __init__(self, parent=None):
        super(Settings, self).__init__(parent)
        self.ui = Ui_Settings()
        self.ui.setupUi(self)
        self.ui.shadowsocksAddButton.clicked.connect(self.addSS)
        self.ui.parentRemoveButton.clicked.connect(self.delParent)
        self.ui.editConfButton.clicked.connect(self.openconf)
        self.ui.editLocalButton.clicked.connect(self.openlocal)
        self.ui.gfwlistToggle.stateChanged.connect(self.gfwlistToggle)
        self.ui.updateToggle.stateChanged.connect(self.autoUpdateToggle)
        self.ref.connect(self.refresh)
        self.port = parent.port
        self.icon = parent
        setFont(self.ui.ssMethodBox)
        header = [tr("MainWindow", "name", None, QtGui.QApplication.UnicodeUTF8),
                  tr("MainWindow", "address", None, QtGui.QApplication.UnicodeUTF8),
                  tr("MainWindow", "priority", None, QtGui.QApplication.UnicodeUTF8)]
        data = []
        self.table_model = MyTableModel(self, data, header)
        self.ui.tableView.setModel(self.table_model)

        import encrypt
        l = ['']
        l.extend(sorted(encrypt.method_supported.keys()))
        self.ui.ssMethodBox.addItems(l)

    def refresh(self):
        try:
            data = json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/parent' % self.port, timeout=1).read().decode())
            self.table_model.update(data)
            self.ui.tableView.resizeRowsToContents()
            self.ui.tableView.resizeColumnsToContents()
            self.ui.gfwlistToggle.setCheckState(QtCore.Qt.CheckState.Checked if json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/gfwlist' % self.port, timeout=1).read().decode()) else QtCore.Qt.CheckState.Unchecked)
            self.ui.updateToggle.setCheckState(QtCore.Qt.CheckState.Checked if json.loads(urllib2.urlopen('http://127.0.0.1:%d/api/autoupdate' % self.port, timeout=1).read().decode()) else QtCore.Qt.CheckState.Unchecked)
        except:
            pass

    def addSS(self):
        sName = self.ui.ssNameEdit.text()
        sServer = self.ui.ssServerEdit.text()
        sPort = self.ui.ssPortEdit.text()
        sMethod = self.ui.ssMethodBox.currentText()
        sPass = self.ui.ssPassEdit.text()
        sPriority = self.ui.ssPriorityEdit.text()

        if not sName:
            sName = '%s-%s' % (sServer, sPort)
        if not sPriority:
            sPriority = 99
        if not all([sServer, sPort.isdigit(), sMethod, sPass]):
            self.icon.showMessage(tr("MainWindow", "error_notice", None, QtGui.QApplication.UnicodeUTF8))
            return
        data = json.dumps((sName, ('ss://%s:%s@%s:%s %s' % (urlquote(sMethod), urlquote(sPass), sServer, sPort, sPriority)))).encode()
        try:
            urllib2.urlopen('http://127.0.0.1:%d/api/parent' % self.port, data, timeout=1).read()
        except:
            self.icon.showMessage('add parent %s failed!' % sName)
        else:
            self.ui.ssNameEdit.clear()
            self.ui.ssServerEdit.clear()
            self.ui.ssPortEdit.clear()
            self.ui.ssPassEdit.clear()
            self.ui.ssPriorityEdit.clear()

    def gfwlistToggle(self):
        urllib2.urlopen('http://127.0.0.1:%d/api/gfwlist' % self.port, json.dumps(self.ui.gfwlistToggle.isChecked()).encode(), timeout=1).read()

    def autoUpdateToggle(self):
        urllib2.urlopen('http://127.0.0.1:%d/api/autoupdate' % self.port, json.dumps(self.ui.updateToggle.isChecked()).encode(), timeout=1).read()

    def delParent(self):
        index = self.ui.tableView.currentIndex().row()
        conn = httplib.HTTPConnection('127.0.0.1', self.port, timeout=1)
        conn.request('DELETE', '/api/parent/%s' % (self.table_model.mylist[index][0]))
        resp = conn.getresponse()
        content = resp.read()
        print(content)

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
        self.icon.showMessage(tr("MainWindow", "reload_notice", None, QtGui.QApplication.UnicodeUTF8))


class MyTableModel(QtCore.QAbstractTableModel):
    def __init__(self, parent, mylist, header, *args):
        QtCore.QAbstractTableModel.__init__(self, parent, *args)
        self.mylist = mylist
        self.header = header

    def rowCount(self, parent):
        return len(self.mylist)

    def columnCount(self, parent):
        return len(self.header)

    def data(self, index, role):
        if not index.isValid():
            return None
        elif role != QtCore.Qt.DisplayRole:
            return None
        return self.mylist[index.row()][index.column()]

    def update(self, mylist):
        self.emit(QtCore.SIGNAL("layoutAboutToBeChanged()"))
        self.mylist = mylist
        self.emit(QtCore.SIGNAL("layoutChanged()"))

    def headerData(self, col, orientation, role):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.header[col]
        return None

    def sort(self, col, order):
        """sort table by given column number col"""
        self.emit(QtCore.SIGNAL("layoutAboutToBeChanged()"))
        self.mylist = sorted(self.mylist, key=operator.itemgetter(col))
        if order == QtCore.Qt.DescendingOrder:
            self.mylist.reverse()
        self.emit(QtCore.SIGNAL("layoutChanged()"))


@atexit.register
def atexit_do():
    if sys.platform.startswith('win'):
        setIEproxy(0)
    try:
        win.killProcess()
    except:
        pass


if __name__ == "__main__":
    if os.name == 'nt':
        try:
            import ctypes
            myappid = 'v3aqb.fgfw-lite'  # arbitrary string
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except:
            pass
    app = QtGui.QApplication('')
    win = MainWindow()
    sys.exit(app.exec_())
