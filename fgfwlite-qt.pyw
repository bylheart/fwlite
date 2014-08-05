#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')), 'fgfw-lite'))
from collections import deque
from PySide import QtCore, QtGui
from ui_mainwindow import Ui_MainWindow
try:
    import pynotify
    pynotify.init('FGFW-Lite Notify')
except ImportError:
    pynotify = None
WORKINGDIR = os.path.dirname(os.path.abspath(__file__).replace('\\', '/'))
os.chdir(WORKINGDIR)

TRAY_ICON = '%s/fgfw-lite/ui/taskbar.ico' % WORKINGDIR
PYTHON = '%s/Python27/python27.exe' % WORKINGDIR if sys.platform.startswith('win') else '/usr/bin/env python2.7'


class MainWindow(QtGui.QMainWindow):
    trigger = QtCore.Signal(str)

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
        self.runner = None
        self.createActions()
        self.createTrayIcon()
        self.createProcess()

    def createProcess(self):
        if self.runner:
            self.runner.kill()
        self.runner = QtCore.QProcess(self)
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
        self.setIE8118Action = QtGui.QAction(u"智能代理8118", self, triggered=self.setIEproxy8118)
        self.setIE8119Action = QtGui.QAction(u"全局代理8119", self, triggered=self.setIEproxy8119)
        self.setIENoneAction = QtGui.QAction(u"直接连接", self, triggered=self.setIEproxyNone)
        self.openlocalAction = QtGui.QAction(u"local.txt", self, triggered=self.openlocal)
        self.openconfAction = QtGui.QAction(u"userconf.ini", self, triggered=self.openconf)
        self.quitAction = QtGui.QAction(u"退出", self, triggered=self.on_Quit)

    def createTrayIcon(self):
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.showToggleAction)
        self.trayIconMenu.addAction(self.reloadAction)

        if sys.platform.startswith('win'):
            settingIEproxyMenu = self.trayIconMenu.addMenu(u'设置代理')
            settingIEproxyMenu.addAction(self.setIE8118Action)
            settingIEproxyMenu.addAction(self.setIE8119Action)
            settingIEproxyMenu.addAction(self.setIENoneAction)

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

    def setIEproxy8118(self):
        self.setIEproxy(1, u'127.0.0.1:8118')

    def setIEproxy8119(self):
        self.setIEproxy(1, u'127.0.0.1:8119')

    def setIEproxyNone(self):
        self.setIEproxy(0)

    def setIEproxy(self, enable, proxy=u'', override=u'<local>'):
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
            return self.showMessage('OS not supported')
        os.system('%s %s' % (cmd, path))
        self.showMessage(u'新的设置将在重新载入后生效')

    def on_Quit(self):
        QtGui.qApp.quit()

    def send(self):
        te = self.ui.lineEdit.text()
        self.ui.lineEdit.clear()
        self.update_text(te)

    def update_text(self, text):
        if text.strip():
            self.consoleText.append(text)
            self.ui.console.setPlainText(u'\n'.join(self.consoleText))
            self.ui.console.moveCursor(QtGui.QTextCursor.End)

    def showToggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            if self.isMinimized():
                self.showNormal()
            self.activateWindow()

    def reload(self):
        self.ui.console.clear()
        self.consoleText = deque(maxlen=300)
        self.createProcess()

if __name__ == "__main__":
    if os.name == 'nt':
        import ctypes
        myappid = 'v3aqb.fgfw-lite'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    app = QtGui.QApplication('')
    win = MainWindow()
    sys.exit(app.exec_())
