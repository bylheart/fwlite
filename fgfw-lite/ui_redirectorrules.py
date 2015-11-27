# -*- coding: utf-8 -*-
import translate
tr = translate.translate.translate
# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './fgfw-lite/ui\redirectorrules.ui'
#
# Created: Sat Nov 28 05:32:50 2015
#      by: pyside-uic 0.2.15 running on PySide 1.2.2
#
# WARNING! All changes made in this file will be lost!

from PySide import QtCore, QtGui

class Ui_RedirectorRules(object):
    def setupUi(self, RedirectorRules):
        RedirectorRules.setObjectName("RedirectorRules")
        RedirectorRules.resize(400, 300)
        RedirectorRules.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.verticalLayout = QtGui.QVBoxLayout(RedirectorRules)
        self.verticalLayout.setObjectName("verticalLayout")
        self.scrollArea = QtGui.QScrollArea(RedirectorRules)
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
        self.RedirectorRulesLayout = QtGui.QVBoxLayout()
        self.RedirectorRulesLayout.setObjectName("RedirectorRulesLayout")
        self.verticalLayout_3.addLayout(self.RedirectorRulesLayout)
        self.verticalLayout_2.addWidget(self.widget)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scrollArea)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtGui.QLabel(RedirectorRules)
        self.label.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.RuleEdit = QtGui.QLineEdit(RedirectorRules)
        self.RuleEdit.setObjectName("RuleEdit")
        self.horizontalLayout.addWidget(self.RuleEdit)
        self.label_2 = QtGui.QLabel(RedirectorRules)
        self.label_2.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout.addWidget(self.label_2)
        self.DestEdit = QtGui.QLineEdit(RedirectorRules)
        self.DestEdit.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.DestEdit.setObjectName("DestEdit")
        self.horizontalLayout.addWidget(self.DestEdit)
        self.AddRedirectorRuleButton = QtGui.QPushButton(RedirectorRules)
        self.AddRedirectorRuleButton.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedStates))
        self.AddRedirectorRuleButton.setObjectName("AddRedirectorRuleButton")
        self.horizontalLayout.addWidget(self.AddRedirectorRuleButton)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(RedirectorRules)
        QtCore.QMetaObject.connectSlotsByName(RedirectorRules)

    def retranslateUi(self, RedirectorRules):
        RedirectorRules.setWindowTitle(tr("RedirectorRules", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(tr("RedirectorRules", "Add Rule", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(tr("RedirectorRules", "Redirect to", None, QtGui.QApplication.UnicodeUTF8))
        self.AddRedirectorRuleButton.setText(tr("RedirectorRules", "Add", None, QtGui.QApplication.UnicodeUTF8))

