# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'createelectiondialog.ui'
#
# Created: Mon Feb 24 13:04:26 2014
#      by: PyQt4 UI code generator 4.10.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_CreateElectionDialog(object):
    def setupUi(self, CreateElectionDialog):
        CreateElectionDialog.setObjectName(_fromUtf8("CreateElectionDialog"))
        CreateElectionDialog.resize(400, 439)
        self.formLayout = QtGui.QFormLayout(CreateElectionDialog)
        self.formLayout.setFieldGrowthPolicy(QtGui.QFormLayout.AllNonFixedFieldsGrow)
        self.formLayout.setObjectName(_fromUtf8("formLayout"))
        self.label = QtGui.QLabel(CreateElectionDialog)
        self.label.setObjectName(_fromUtf8("label"))
        self.formLayout.setWidget(0, QtGui.QFormLayout.LabelRole, self.label)
        self.lineEditQuestion = QtGui.QLineEdit(CreateElectionDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineEditQuestion.sizePolicy().hasHeightForWidth())
        self.lineEditQuestion.setSizePolicy(sizePolicy)
        self.lineEditQuestion.setObjectName(_fromUtf8("lineEditQuestion"))
        self.formLayout.setWidget(1, QtGui.QFormLayout.SpanningRole, self.lineEditQuestion)
        self.label_2 = QtGui.QLabel(CreateElectionDialog)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.formLayout.setWidget(2, QtGui.QFormLayout.LabelRole, self.label_2)
        self.pushButtonAddAnswer = QtGui.QPushButton(CreateElectionDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonAddAnswer.sizePolicy().hasHeightForWidth())
        self.pushButtonAddAnswer.setSizePolicy(sizePolicy)
        self.pushButtonAddAnswer.setObjectName(_fromUtf8("pushButtonAddAnswer"))
        self.formLayout.setWidget(2, QtGui.QFormLayout.FieldRole, self.pushButtonAddAnswer)
        self.listWidgetAnswers = QtGui.QListWidget(CreateElectionDialog)
        self.listWidgetAnswers.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.listWidgetAnswers.sizePolicy().hasHeightForWidth())
        self.listWidgetAnswers.setSizePolicy(sizePolicy)
        self.listWidgetAnswers.setObjectName(_fromUtf8("listWidgetAnswers"))
        self.formLayout.setWidget(3, QtGui.QFormLayout.SpanningRole, self.listWidgetAnswers)
        self.label_3 = QtGui.QLabel(CreateElectionDialog)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.formLayout.setWidget(5, QtGui.QFormLayout.LabelRole, self.label_3)
        self.pushButtonAddVoter = QtGui.QPushButton(CreateElectionDialog)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonAddVoter.sizePolicy().hasHeightForWidth())
        self.pushButtonAddVoter.setSizePolicy(sizePolicy)
        self.pushButtonAddVoter.setObjectName(_fromUtf8("pushButtonAddVoter"))
        self.formLayout.setWidget(5, QtGui.QFormLayout.FieldRole, self.pushButtonAddVoter)
        self.listWidgetVoters = QtGui.QListWidget(CreateElectionDialog)
        self.listWidgetVoters.setObjectName(_fromUtf8("listWidgetVoters"))
        self.formLayout.setWidget(6, QtGui.QFormLayout.SpanningRole, self.listWidgetVoters)
        self.buttonBox = QtGui.QDialogButtonBox(CreateElectionDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.formLayout.setWidget(7, QtGui.QFormLayout.SpanningRole, self.buttonBox)

        self.retranslateUi(CreateElectionDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), CreateElectionDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), CreateElectionDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(CreateElectionDialog)

    def retranslateUi(self, CreateElectionDialog):
        CreateElectionDialog.setWindowTitle(_translate("CreateElectionDialog", "Dialog", None))
        self.label.setText(_translate("CreateElectionDialog", "Election question", None))
        self.label_2.setText(_translate("CreateElectionDialog", "Possible answers", None))
        self.pushButtonAddAnswer.setText(_translate("CreateElectionDialog", "Add", None))
        self.label_3.setText(_translate("CreateElectionDialog", "Registered voters", None))
        self.pushButtonAddVoter.setText(_translate("CreateElectionDialog", "Add", None))

