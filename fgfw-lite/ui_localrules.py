# -*- coding: utf-8 -*-
import translate
tr = translate.translate
# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\localrules.ui'
#
# Created: Tue May 10 02:38:44 2016
#      by: pyside-uic 0.2.15 running on PySide 1.2.4
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_LocalRules(object):
    def setupUi(self, LocalRules):
        LocalRules.setObjectName("LocalRules")
        LocalRules.resize(400, 300)
        LocalRules.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.verticalLayout = QtGui.QVBoxLayout(LocalRules)
        self.verticalLayout.setObjectName("verticalLayout")
        self.scrollArea = QtGui.QScrollArea(LocalRules)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtGui.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 380, 249))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.widget = QtGui.QWidget(self.scrollAreaWidgetContents)
        self.widget.setObjectName("widget")
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.widget)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.LocalRulesLayout = QtGui.QVBoxLayout()
        self.LocalRulesLayout.setObjectName("LocalRulesLayout")
        self.verticalLayout_3.addLayout(self.LocalRulesLayout)
        self.verticalLayout_2.addWidget(self.widget)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scrollArea)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(LocalRules)
        self.label.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.LocalRuleEdit = QtGui.QLineEdit(LocalRules)
        self.LocalRuleEdit.setObjectName("LocalRuleEdit")
        self.horizontalLayout.addWidget(self.LocalRuleEdit)
        self.label_2 = QtGui.QLabel(LocalRules)
        self.label_2.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout.addWidget(self.label_2)
        self.ExpireEdit = QtGui.QLineEdit(LocalRules)
        self.ExpireEdit.setMaximumSize(QtCore.QSize(50, 16777215))
        self.ExpireEdit.setObjectName("ExpireEdit")
        self.horizontalLayout.addWidget(self.ExpireEdit)
        self.label_3 = QtGui.QLabel(LocalRules)
        self.label_3.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.label_3.setObjectName("label_3")
        self.horizontalLayout.addWidget(self.label_3)
        self.AddLocalRuleButton = QtGui.QPushButton(LocalRules)
        self.AddLocalRuleButton.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.AddLocalRuleButton.setObjectName("AddLocalRuleButton")
        self.horizontalLayout.addWidget(self.AddLocalRuleButton)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(LocalRules)
        QtCore.QMetaObject.connectSlotsByName(LocalRules)

    def retranslateUi(self, LocalRules):
        LocalRules.setWindowTitle(tr("LocalRules", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(tr("LocalRules", "Add Rule", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(tr("LocalRules", "Expires", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(tr("LocalRules", "Minutes", None, QtGui.QApplication.UnicodeUTF8))
        self.AddLocalRuleButton.setText(tr("LocalRules", "Add", None, QtGui.QApplication.UnicodeUTF8))

