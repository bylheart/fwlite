# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\mainwindow.ui'
#
# Created: Sat Aug 02 00:53:21 2014
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(640, 480)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtGui.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.console = QtGui.QPlainTextEdit(self.centralwidget)
        self.console.setAcceptDrops(False)
        self.console.setAutoFillBackground(True)
        self.console.setUndoRedoEnabled(False)
        self.console.setReadOnly(True)
        self.console.setObjectName("console")
        self.verticalLayout.addWidget(self.console)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "FGFW-Lite", None, QtGui.QApplication.UnicodeUTF8))

