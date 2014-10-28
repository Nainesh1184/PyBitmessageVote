# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'timestampersettingsdialog.ui'
#
# Created: Tue Oct 21 12:09:19 2014
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

class Ui_TimestamperSettingsDialog(object):
    def setupUi(self, TimestamperSettingsDialog):
        TimestamperSettingsDialog.setObjectName(_fromUtf8("TimestamperSettingsDialog"))
        TimestamperSettingsDialog.resize(545, 460)
        self.verticalLayout = QtGui.QVBoxLayout(TimestamperSettingsDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.checkBoxTimestamper = QtGui.QCheckBox(TimestamperSettingsDialog)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.checkBoxTimestamper.setFont(font)
        self.checkBoxTimestamper.setObjectName(_fromUtf8("checkBoxTimestamper"))
        self.horizontalLayout_3.addWidget(self.checkBoxTimestamper)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.label = QtGui.QLabel(TimestamperSettingsDialog)
        self.label.setTextFormat(QtCore.Qt.RichText)
        self.label.setWordWrap(True)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.pushButtonImportBitcoinAddress = QtGui.QPushButton(TimestamperSettingsDialog)
        self.pushButtonImportBitcoinAddress.setObjectName(_fromUtf8("pushButtonImportBitcoinAddress"))
        self.horizontalLayout.addWidget(self.pushButtonImportBitcoinAddress)
        self.pushButtonRefreshBalances = QtGui.QPushButton(TimestamperSettingsDialog)
        self.pushButtonRefreshBalances.setObjectName(_fromUtf8("pushButtonRefreshBalances"))
        self.horizontalLayout.addWidget(self.pushButtonRefreshBalances)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tableWidgetAddresses = QtGui.QTableWidget(TimestamperSettingsDialog)
        self.tableWidgetAddresses.setAlternatingRowColors(False)
        self.tableWidgetAddresses.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        self.tableWidgetAddresses.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.tableWidgetAddresses.setObjectName(_fromUtf8("tableWidgetAddresses"))
        self.tableWidgetAddresses.setColumnCount(3)
        self.tableWidgetAddresses.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetAddresses.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetAddresses.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignVCenter)
        self.tableWidgetAddresses.setHorizontalHeaderItem(2, item)
        self.tableWidgetAddresses.horizontalHeader().setDefaultSectionSize(175)
        self.tableWidgetAddresses.horizontalHeader().setStretchLastSection(True)
        self.tableWidgetAddresses.verticalHeader().setVisible(False)
        self.tableWidgetAddresses.verticalHeader().setHighlightSections(False)
        self.verticalLayout.addWidget(self.tableWidgetAddresses)
        self.buttonBox = QtGui.QDialogButtonBox(TimestamperSettingsDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout.setStretch(3, 1)

        self.retranslateUi(TimestamperSettingsDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), TimestamperSettingsDialog.reject)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), TimestamperSettingsDialog.accept)
        QtCore.QMetaObject.connectSlotsByName(TimestamperSettingsDialog)

    def retranslateUi(self, TimestamperSettingsDialog):
        TimestamperSettingsDialog.setWindowTitle(_translate("TimestamperSettingsDialog", "Bitcoin addresses", None))
        self.checkBoxTimestamper.setText(_translate("TimestamperSettingsDialog", "Contribute by acting as a timestamper", None))
        self.label.setText(_translate("TimestamperSettingsDialog", "By being a timestamper, you contribute to the execution of the election by taking part in the commitment and results phases of the election.<br><br>To be a timestamper, you must agree to possibly spend a very small amount of bitcoin (0.00010001 BTC / 10001 satoshi) during the election. This is used to prove that a commitment was created before the deadline and thus ensure that only votes cast before the deadline can be validated as such.<br><br><b>The election cannot be executed if nobody volunteers as timestamper!</b><br><br>Below you can select bitcoin addresses which correspond to your private Bitmessage identities which have enough bitcoins available to use for our purpose. You can either transfer bitcoins to on of those, or import a bitcoin address from a known private key.", None))
        self.pushButtonImportBitcoinAddress.setText(_translate("TimestamperSettingsDialog", "Import bitcoin address", None))
        self.pushButtonRefreshBalances.setText(_translate("TimestamperSettingsDialog", "Refresh balances", None))
        item = self.tableWidgetAddresses.horizontalHeaderItem(0)
        item.setText(_translate("TimestamperSettingsDialog", "Bitmessage address", None))
        item = self.tableWidgetAddresses.horizontalHeaderItem(1)
        item.setText(_translate("TimestamperSettingsDialog", "Bitcoin address", None))
        item = self.tableWidgetAddresses.horizontalHeaderItem(2)
        item.setText(_translate("TimestamperSettingsDialog", "Balance", None))

