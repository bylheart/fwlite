#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('\\', '/')), 'fgfw-lite'))
import threading
from PySide import QtCore, QtGui
from ui_mainwindow import Ui_MainWindow

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
        if os.name == 'nt':
            font = QtGui.QFont()
            font.setFamily("Consolas")
            self.ui.console.setFont(font)
        else:
            font = QtGui.QFont()
            font.setFamily("Droid Sans Mono")
            self.ui.console.setFont(font)
        self.ui.console.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
        self._lock = threading.Lock()
        self.runner = None
        self.setWindowIcon(QtGui.QIcon(TRAY_ICON))
        self.center()
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
        self.quitAction = QtGui.QAction(u"退出", self, triggered=self.on_Quit)

    def createTrayIcon(self):
        self.trayIconMenu = QtGui.QMenu(self)
        self.trayIconMenu.addAction(self.showToggleAction)
        self.trayIconMenu.addAction(self.reloadAction)
        self.trayIconMenu.addSeparator()
        self.trayIconMenu.addAction(self.quitAction)

        self.trayIcon = QtGui.QSystemTrayIcon(self)
        self.trayIcon.setContextMenu(self.trayIconMenu)
        self.trayIcon.setIcon(QtGui.QIcon(TRAY_ICON))
        self.trayIcon.activated.connect(self.on_trayActive)
        self.trayIcon.show()

    def closeEvent(self, event):
        if self.trayIcon.isVisible():
            self.hide()
        event.ignore()

    def on_trayActive(self, reason):
        if reason is self.trayIcon.Trigger:
            self.showToggle()

    def on_Quit(self):
        QtGui.qApp.quit()

    def send(self):
        te = self.ui.lineEdit.text()
        self.ui.lineEdit.clear()
        self.update_text(te)

    def update_text(self, text):
        if text:
            if len(self.ui.console.toPlainText().splitlines()) > 300:
                self.ui.console.setPlainText(u'\n'.join(self.ui.console.toPlainText().splitlines()[-100:]))
            self.ui.console.moveCursor(QtGui.QTextCursor.End)
            self.ui.console.appendPlainText(text)

    def showToggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.activateWindow()

    def reload(self):
        self.ui.console.clear()
        self.createProcess()

if __name__ == "__main__":
    app = QtGui.QApplication('')
    win = MainWindow()
    sys.exit(app.exec_())
