# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\localrule.ui'
#
# Created: Tue Aug 19 00:19:06 2014
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_LocalRule(object):
    def setupUi(self, LocalRule):
        LocalRule.setObjectName("LocalRule")
        LocalRule.resize(232, 23)
        self.horizontalLayout = QtGui.QHBoxLayout(LocalRule)
        self.horizontalLayout.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit = QtGui.QLineEdit(LocalRule)
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        self.delButton = QtGui.QPushButton(LocalRule)
        self.delButton.setObjectName("delButton")
        self.horizontalLayout.addWidget(self.delButton)

        self.retranslateUi(LocalRule)
        QtCore.QMetaObject.connectSlotsByName(LocalRule)

    def retranslateUi(self, LocalRule):
        LocalRule.setWindowTitle(QtGui.QApplication.translate("LocalRule", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.delButton.setText(QtGui.QApplication.translate("LocalRule", "删除", None, QtGui.QApplication.UnicodeUTF8))

