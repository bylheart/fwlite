# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\localrules.ui'
#
# Created: Mon Aug 18 12:11:07 2014
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_LocalRules(object):
    def setupUi(self, LocalRules):
        LocalRules.setObjectName("LocalRules")
        LocalRules.resize(400, 300)
        self.verticalLayout = QtGui.QVBoxLayout(LocalRules)
        self.verticalLayout.setObjectName("verticalLayout")
        self.LocalRulesLayout = QtGui.QVBoxLayout()
        self.LocalRulesLayout.setObjectName("LocalRulesLayout")
        self.verticalLayout.addLayout(self.LocalRulesLayout)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(LocalRules)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.LocalRuleEdit = QtGui.QLineEdit(LocalRules)
        self.LocalRuleEdit.setObjectName("LocalRuleEdit")
        self.horizontalLayout.addWidget(self.LocalRuleEdit)
        self.label_2 = QtGui.QLabel(LocalRules)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout.addWidget(self.label_2)
        self.ExpireEdit = QtGui.QLineEdit(LocalRules)
        self.ExpireEdit.setMaximumSize(QtCore.QSize(50, 16777215))
        self.ExpireEdit.setObjectName("ExpireEdit")
        self.horizontalLayout.addWidget(self.ExpireEdit)
        self.label_3 = QtGui.QLabel(LocalRules)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout.addWidget(self.label_3)
        self.AddLocalRuleButton = QtGui.QPushButton(LocalRules)
        self.AddLocalRuleButton.setObjectName("AddLocalRuleButton")
        self.horizontalLayout.addWidget(self.AddLocalRuleButton)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout.setStretch(0, 6)

        self.retranslateUi(LocalRules)
        QtCore.QMetaObject.connectSlotsByName(LocalRules)

    def retranslateUi(self, LocalRules):
        LocalRules.setWindowTitle(QtGui.QApplication.translate("LocalRules", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("LocalRules", "添加规则", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("LocalRules", "有效期", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("LocalRules", "分钟", None, QtGui.QApplication.UnicodeUTF8))
        self.AddLocalRuleButton.setText(QtGui.QApplication.translate("LocalRules", "添加", None, QtGui.QApplication.UnicodeUTF8))

