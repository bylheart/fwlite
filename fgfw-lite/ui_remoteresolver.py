# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\remoteresolver.ui'
#
# Created: Thu Nov 26 00:13:16 2015
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_remote_resolver(object):
    def setupUi(self, remote_resolver):
        remote_resolver.setObjectName("remote_resolver")
        remote_resolver.resize(300, 200)
        remote_resolver.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.verticalLayoutWidget = QtGui.QWidget(remote_resolver)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 4, 301, 191))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtGui.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.formLayout = QtGui.QFormLayout()
        self.formLayout.setFieldGrowthPolicy(QtGui.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setObjectName("formLayout")
        self.hostLabel = QtGui.QLabel(self.verticalLayoutWidget)
        self.hostLabel.setObjectName("hostLabel")
        self.formLayout.setWidget(0, QtGui.QFormLayout.LabelRole, self.hostLabel)
        self.hostLineEdit = QtGui.QLineEdit(self.verticalLayoutWidget)
        self.hostLineEdit.setObjectName("hostLineEdit")
        self.formLayout.setWidget(0, QtGui.QFormLayout.FieldRole, self.hostLineEdit)
        self.serverLabel = QtGui.QLabel(self.verticalLayoutWidget)
        self.serverLabel.setObjectName("serverLabel")
        self.formLayout.setWidget(1, QtGui.QFormLayout.LabelRole, self.serverLabel)
        self.serverlineEdit = QtGui.QLineEdit(self.verticalLayoutWidget)
        self.serverlineEdit.setObjectName("serverlineEdit")
        self.formLayout.setWidget(1, QtGui.QFormLayout.FieldRole, self.serverlineEdit)
        self.verticalLayout.addLayout(self.formLayout)
        self.goButton = QtGui.QPushButton(self.verticalLayoutWidget)
        self.goButton.setObjectName("goButton")
        self.verticalLayout.addWidget(self.goButton)
        self.resultTextEdit = QtGui.QPlainTextEdit(self.verticalLayoutWidget)
        self.resultTextEdit.setAcceptDrops(False)
        self.resultTextEdit.setUndoRedoEnabled(False)
        self.resultTextEdit.setReadOnly(True)
        self.resultTextEdit.setObjectName("resultTextEdit")
        self.verticalLayout.addWidget(self.resultTextEdit)

        self.retranslateUi(remote_resolver)
        QtCore.QMetaObject.connectSlotsByName(remote_resolver)

    def retranslateUi(self, remote_resolver):
        remote_resolver.setWindowTitle(QtGui.QApplication.translate("remote_resolver", "FW-Lite Remote Resolver", None, QtGui.QApplication.UnicodeUTF8))
        self.hostLabel.setText(QtGui.QApplication.translate("remote_resolver", "Hostname:", None, QtGui.QApplication.UnicodeUTF8))
        self.hostLineEdit.setText(QtGui.QApplication.translate("remote_resolver", "www.google.com", None, QtGui.QApplication.UnicodeUTF8))
        self.serverLabel.setText(QtGui.QApplication.translate("remote_resolver", "DNS Server:", None, QtGui.QApplication.UnicodeUTF8))
        self.serverlineEdit.setText(QtGui.QApplication.translate("remote_resolver", "8.8.8.8", None, QtGui.QApplication.UnicodeUTF8))
        self.goButton.setText(QtGui.QApplication.translate("remote_resolver", "Resolve", None, QtGui.QApplication.UnicodeUTF8))

