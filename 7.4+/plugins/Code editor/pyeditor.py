# Created by Storm Shadow www.techbliss.org
print("\n") #getting the box fit
print(" ###################################################\n" \
    " #         Author Storm Shadow, bruce30262         # \n" \
    " #                   Hotkeys                       # \n" \
    " #         Open editor:        Ctrl+H              #\n" \
    " #         NewFile:            Ctrl+N              #\n" \
    " #         OpenFile:           Ctrl+O              #\n" \
    " #         SaveFile:           Ctrl+S              #\n" \
    " #         Save As New File:   Ctrl+Shift+ S       #\n" \
    " #         RunScript:          Ctrl+E              #\n" \
    " #         Undo:               Ctrl+Z              #\n" \
    " #         Redo:               Ctrl+Shift+Z        #\n" \
    " #         SelectALL:          Ctrl+A              #\n" \
    " #         Paste:              Ctrl+V              #\n" \
    " #         Font:               Ctrl+F              #\n" \
    " #         ResetFolding:       Ctrl+R              #\n" \
    " #         CircleFolding:      Ctrl+C              #\n" \
    " #         PlainFolding:       Ctrl+P              #\n" \
    " #         HEX-ray Home:       Ctrl+W              #\n" \
    " #         IDA Pro Python SDK  Ctrl+I              #\n" \
    " #         IDAPROPythonGit:    Ctrl+G              #\n" \
    " #         Author:             Ctrl+B              #\n" \
    " #         Enable Reg:         Alt+E               #\n" \
    " #         Disable Reg:        Alt+D               #\n" \
    " #         Zoom in             Ctrl+Shift+ +       #\n" \
    " #         Zoom Out            Ctrl+Shift+ -       #\n" \
    " #         Profile Code        Ctrl+Shift+ E       #\n" \
    " ###################################################\n" \
    " #              IDA PRO python Editor              #\n" \
    " ###################################################\n")

import os
import sys
import pickle
import qdarkstyle

from idc import *
from idaapi import *

try:
    dn = os.path.dirname(os.path.abspath(__file__))
except NameError:
    dn = os.getcwd()

TemplateFile = os.path.join(dn, "template", "Plugin_temp")

sys.path.insert(0, dn)
sys.path.insert(0, os.path.join(os.getcwd(), 'icons'))
sys.path.insert(0, os.path.join(os.getcwd(), 'template'))

import PyQt5
from PyQt5 import QtCore, QtGui, QtWidgets, Qsci
from PyQt5.Qsci import QsciScintilla, QsciLexerPython
from PyQt5.QtGui import QFont, QFontMetrics, QColor
from PyQt5.QtWidgets import QDialog, QMessageBox, QWizard, QWizardPage
from PyQt5.QtCore import QCoreApplication

plugin_path = ""
if sys.platform == "win32":
    if hasattr(sys, "frozen"):
        plugin_path = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "PyQt5", "plugins")
        QCoreApplication.addLibraryPath(plugin_path)
    else:
        import site
        for dir in site.getsitepackages():
            QCoreApplication.addLibraryPath(os.path.join(dir, "PyQt5", "plugins"))

elif sys.platform == "darwin":
    plugin_path = os.path.join(QCoreApplication.getInstallPrefix(), "Resources", "plugins")

if plugin_path:
    QCoreApplication.addLibraryPath(plugin_path)

if hasattr(QtCore.Qt, 'AA_EnableHighDpiScaling'):
    PyQt5.QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)

if hasattr(QtCore.Qt, 'AA_UseHighDpiPixmaps'):
    PyQt5.QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
try:
    import ico
except ImportError:
    import icons.ico

try:
    import iconsmore
except ImportError:
    import icons.iconsmore

try:
    import icons3
except ImportError:
    import icons.icons3

try:
    import iconf
except ImportError:
    import icons.iconf

try:
    import icon4
except ImportError:
    pass

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s
try:
    _encoding = QtWidgets.QApplication.UnicodeUTF8

    def _translate(context, text, disambig):
        return QtWidgets.QApplication.translate(context, text,
                disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtWidgets.QApplication.translate(context, text, disambig)

class Ui_messageformForm(QtWidgets.QWidget):
    def setupUi1(self, messageformForm):
        messageformForm.setObjectName("messageformForm")
        messageformForm.resize(404, 169)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(messageformForm.sizePolicy().hasHeightForWidth())
        messageformForm.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        messageformForm.setFont(font)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/icons/twa.gif"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        messageformForm.setWindowIcon(icon2)
        self.label = QtWidgets.QLabel(messageformForm)
        self.label.setGeometry(QtCore.QRect(40, 20, 341, 111))
        font = QtGui.QFont()
        font.setPointSize(19)
        self.label.setFont(font)
        self.label.setObjectName("label")

        self.retranslateUi(messageformForm)
        QtCore.QMetaObject.connectSlotsByName(messageformForm)

    def retranslateUi(self, messageformForm):
        _translate = QtCore.QCoreApplication.translate
        messageformForm.setWindowTitle(_translate("messageformForm", "Soon to be fixed"))
        self.label.setText(_translate("messageformForm", "Soon to be fixed"))

class Ui_Wizard(QtWidgets.QWizard):
    def __init__(self, parent=None):
        super(Ui_Wizard, self).__init__(parent=None)
        Wizard.setObjectName("Wizard")
        Wizard.resize(762, 500)
        font = QtGui.QFont()
        font.setFamily("Calibri Light")
        Wizard.setFont(font)
        Wizard.setOptions(QtWidgets.QWizard.HelpButtonOnRight)
        self.wizardPage1 = QtWidgets.QWizardPage()
        font = QtGui.QFont()
        font.setFamily("Calibri Light")
        font.setPointSize(20)
        self.wizardPage1.setFont(font)
        self.wizardPage1.setObjectName("wizardPage1")
        self.textBrowser_2 = QtWidgets.QTextBrowser(self.wizardPage1)
        self.textBrowser_2.setGeometry(QtCore.QRect(130, 140, 421, 131))
        self.textBrowser_2.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.textBrowser_2.setObjectName("textBrowser_2")
        Wizard.addPage(self.wizardPage1)
        self.wizardPage = QtWidgets.QWizardPage()
        self.wizardPage.setTitle("")
        self.wizardPage.setSubTitle("")
        self.wizardPage.setObjectName("wizardPage")
        self.textBrowser_4 = QtWidgets.QTextBrowser(self.wizardPage)
        self.textBrowser_4.setGeometry(QtCore.QRect(130, 140, 499, 239))
        self.textBrowser_4.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.textBrowser_4.setObjectName("textBrowser_4")
        Wizard.addPage(self.wizardPage)
        self.tempwizardPage = QtWidgets.QWizardPage()
        self.tempwizardPage.setObjectName("tempwizardPage")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.tempwizardPage)
        self.verticalLayout.setObjectName("verticalLayout")
        self.TemptextEdit = Qsci.QsciScintilla(self.tempwizardPage)
        self.TemptextEdit.setToolTip("")
        self.TemptextEdit.setWhatsThis("")
        self.TemptextEdit.setObjectName("TemptextEdit")
        self.verticalLayout.addWidget(self.TemptextEdit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.temppushButtonopen = QtWidgets.QPushButton(self.tempwizardPage)
        self.temppushButtonopen.setObjectName("temppushButtonopen")
        self.horizontalLayout.addWidget(self.temppushButtonopen)
        self.temppushButtonsave = QtWidgets.QPushButton(self.tempwizardPage)
        self.temppushButtonsave.setObjectName("temppushButtonsave")
        self.horizontalLayout.addWidget(self.temppushButtonsave)
        self.verticalLayout.addLayout(self.horizontalLayout)
        Wizard.addPage(self.tempwizardPage)
        self.scriptwizardPage = QtWidgets.QWizardPage()
        self.scriptwizardPage.setObjectName("scriptwizardPage")
        self.textBrowser_5 = QtWidgets.QTextBrowser(self.scriptwizardPage)
        self.textBrowser_5.setGeometry(QtCore.QRect(120, 130, 499, 239))
        self.textBrowser_5.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.textBrowser_5.setObjectName("textBrowser_5")
        Wizard.addPage(self.scriptwizardPage)
        self.wizardPage_3 = QtWidgets.QWizardPage()
        self.wizardPage_3.setObjectName("wizardPage_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.wizardPage_3)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.script_textEdit = Qsci.QsciScintilla(self.wizardPage_3)
        self.script_textEdit.setToolTip("")
        self.script_textEdit.setWhatsThis("")
        self.script_textEdit.setObjectName("script_textEdit")
        self.verticalLayout_2.addWidget(self.script_textEdit)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.scriptGrabpushButton = QtWidgets.QPushButton(self.wizardPage_3)
        self.scriptGrabpushButton.setObjectName("scriptGrabpushButton")
        self.horizontalLayout_2.addWidget(self.scriptGrabpushButton)
        self.scriptpushButtonopen = QtWidgets.QPushButton(self.wizardPage_3)
        self.scriptpushButtonopen.setObjectName("scriptpushButtonopen")
        self.horizontalLayout_2.addWidget(self.scriptpushButtonopen)
        self.scriptpushButtonsave = QtWidgets.QPushButton(self.wizardPage_3)
        self.scriptpushButtonsave.setObjectName("scriptpushButtonsave")
        self.horizontalLayout_2.addWidget(self.scriptpushButtonsave)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        Wizard.addPage(self.wizardPage_3)
        self.wizardPage_2 = QtWidgets.QWizardPage()
        font = QtGui.QFont()
        font.setPointSize(20)
        self.wizardPage_2.setFont(font)
        self.wizardPage_2.setObjectName("wizardPage_2")
        self.textBrowser_6 = QtWidgets.QTextBrowser(self.wizardPage_2)
        self.textBrowser_6.setGeometry(QtCore.QRect(170, 140, 411, 191))
        self.textBrowser_6.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.textBrowser_6.setObjectName("textBrowser_6")
        Wizard.addPage(self.wizardPage_2)
        #font textedit
        self.skrift = QFont()
        self.skrift.setFamily('Consolas')
        self.skrift.setFixedPitch(True)
        self.skrift.setPointSize(11)
        self.TemptextEdit.setFont(self.skrift)
        self.script_textEdit.setFont(self.skrift)

        #python style temp
        self.lexer = QsciLexerPython(self.TemptextEdit)
        self.lexer.setFont(self.skrift)
        self.lexer.setEolFill(True)
        #Python style scritps
        self.lexer = QsciLexerPython(self.script_textEdit)
        self.lexer.setFont(self.skrift)
        self.lexer.setEolFill(True)
        self.filename = ""
        #python style temp
        self.TemptextEdit.setAutoCompletionThreshold(0)
        self.TemptextEdit.setAutoCompletionThreshold(6)
        self.TemptextEdit.setAutoCompletionThreshold(8)
        self.TemptextEdit.setAutoCompletionSource(Qsci.QsciScintilla.AcsAPIs)

        self.TemptextEdit.setLexer(self.lexer)
        self.TemptextEdit.SendScintilla(QsciScintilla.SCI_STYLESETFONT, 1, b'Consolas')
        #python style script
        self.script_textEdit.setAutoCompletionThreshold(0)
        self.script_textEdit.setAutoCompletionThreshold(6)
        self.script_textEdit.setAutoCompletionThreshold(8)
        self.script_textEdit.setAutoCompletionSource(Qsci.QsciScintilla.AcsAPIs)

        self.script_textEdit.setLexer(self.lexer)
        self.script_textEdit.SendScintilla(QsciScintilla.SCI_STYLESETFONT, 1, b'Consolas')

        #line numbers temp
        fontmetrics = QFontMetrics(self.skrift)
        self.TemptextEdit.setMarginsFont(self.skrift)
        self.TemptextEdit.setMarginWidth(0, fontmetrics.width("00000") + 6)
        self.TemptextEdit.setTabWidth(4)
        #line numbers script
        fontmetrics = QFontMetrics(self.skrift)
        self.script_textEdit.setMarginsFont(self.skrift)
        self.script_textEdit.setMarginWidth(0, fontmetrics.width("00000") + 6)
        self.script_textEdit.setTabWidth(4)

        #brace temp
        self.TemptextEdit.setBraceMatching(QsciScintilla.SloppyBraceMatch)
        #brace script
        self.script_textEdit.setBraceMatching(QsciScintilla.SloppyBraceMatch)

        #auto line tab =4 temp
        self.TemptextEdit.setAutoIndent(True)
        #auto line tab =4 script
        self.script_textEdit.setAutoIndent(True)

        #scrollbar
        self.script_textEdit.SendScintilla(QsciScintilla.SCI_SETHSCROLLBAR, 1)
        try:
            bs = open(TemplateFile).read()
            bba = QtCore.QByteArray(bs)
            self.bts = QtCore.QTextStream(bba)
            self.bheysa = self.bts.readAll()
            self.TemptextEdit.setText(self.bheysa)
            self.TemptextEdit.setMarkerBackgroundColor((QColor(66, 66, 255)))
            marker = self.TemptextEdit.markerDefine(PyQt5.Qsci.QsciScintilla.Rectangle, 2)

            self.TemptextEdit.markerAdd(7, 2)
            self.TemptextEdit.markerAdd(11, 2)
            self.TemptextEdit.markerAdd(12, 2)
            self.TemptextEdit.markerAdd(13, 2)
            self.TemptextEdit.markerAdd(14, 2)
            self.TemptextEdit.markerAdd(15, 2)
            self.TemptextEdit.markerAdd(19, 2)
            self.TemptextEdit.markerAdd(27, 2)
            self.TemptextEdit.markerAdd(34, 2)
            self.TemptextEdit.markerAdd(35, 2)
            self.TemptextEdit.markerAdd(40, 2)
            self.TemptextEdit.markerAdd(41, 2)
            self.TemptextEdit.markerAdd(42, 2)
            self.TemptextEdit.markerAdd(43, 2)
            self.TemptextEdit.markerAdd(44, 2)
            self.TemptextEdit.markerAdd(45, 2)

            self.TemptextEdit.markerAdd(48, 2)
            self.TemptextEdit.markerAdd(50, 2)
            self.TemptextEdit.markerAdd(51, 2)
            self.TemptextEdit.markerAdd(52, 2)
            self.TemptextEdit.markerAdd(53, 2)
            self.TemptextEdit.markerAdd(54, 2)
            self.TemptextEdit.markerAdd(55, 2)

            self.TemptextEdit.markerAdd(62, 2)
            self.TemptextEdit.markerAdd(63, 2)
            self.TemptextEdit.markerAdd(64, 2)

            self.TemptextEdit.markerAdd(67, 2)
            self.TemptextEdit.markerAdd(89, 2)

            self.TemptextEdit.markerAdd(97, 2)
            self.TemptextEdit.markerAdd(98, 2)
            self.TemptextEdit.markerAdd(99, 2)
            self.TemptextEdit.markerAdd(102, 2)
        except:
            self.TemptextEdit.setText('Plugin_temp file not found')
            pass


        self.retranslateUi2(Wizard)
        QtCore.QMetaObject.connectSlotsByName(Wizard)

    def retranslateUi2(self, Wizard):
        _translate = QtCore.QCoreApplication.translate
        Wizard.setWindowTitle(_translate("Wizard", "           IDA Pro Plugin Wizard"))
        self.textBrowser_2.setHtml(_translate("Wizard", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Calibri Light\'; font-size:20pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Welcome to the plugin wizard.</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Please follow the steps in the wizard, to tranform your code, to a full IDA Pro plugin.</p></body></html>"))
        self.textBrowser_4.setHtml(_translate("Wizard", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Calibri Light\'; font-size:8.14286pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:20pt;\">First we create the plugin loader</span></p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:20pt;\">Then we change the higlightet text in the template, and then save the plugin loader in IDA Pro Plugins folder.</span></p></body></html>"))
        self.temppushButtonopen.setText(_translate("Wizard", "Open"))
        self.temppushButtonsave.setText(_translate("Wizard", "Save"))
        self.textBrowser_5.setHtml(_translate("Wizard", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Calibri Light\'; font-size:8.14286pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:20pt;\">Now we grab the editors current script, or open a new script.<br />Remember to save this in the right folder.<br />Plugins\\My_plugin_folder as declared in the template.</span></p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-size:20pt;\"><br /></p></body></html>"))
        self.scriptGrabpushButton.setText(_translate("Wizard", "Grab from Editor"))
        self.scriptpushButtonopen.setText(_translate("Wizard", "Open"))
        self.scriptpushButtonsave.setText(_translate("Wizard", "Save"))
        self.textBrowser_6.setHtml(_translate("Wizard", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Calibri Light\'; font-size:20pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Loader Template should now be in <br />ida pro\\plugin<br />script should be in a subfolder<br />ida pro\\plugin\\Myplugin\\</p>\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">If above are correct your good to go!</p></body></html>"))

        self.temppushButtonopen.clicked.connect(self.opentemp)
        self.temppushButtonsave.clicked.connect(self.savetemp)
        self.scriptpushButtonopen.clicked.connect(self.openscript)
        self.scriptpushButtonsave.clicked.connect(self.savescript)
        self.scriptGrabpushButton.clicked.connect(self.grapper)

    def grapper(self):
        messageformForm.show()

    def opentemp(self):
        self.path = QtCore.QFileInfo(self.filename).path()

        # Get filename and show only .writer files
        (self.filename, _) = \
            QtWidgets.QFileDialog.getOpenFileName(self.wizardPage_3,
                'Open File', self.path,
                'Python Files (*.py *.pyc *.pyw)', '')

        if self.filename:
            with open(self.filename, 'r') as self.file:
                self.TemptextEdit.setText(self.file.read())
        os.chdir(str(self.path))


    def savetemp(self):
        self.path = QtCore.QFileInfo(self.filename).path()
        (self.filename, _) = \
            QtWidgets.QFileDialog.getSaveFileName(self, 'Save as'
                , self.path, 'Python Files (*.py *.pyc *.pyw)')
        if self.filename:
            self.savetexttemp(self.filename)
        os.chdir(str(self.path))

    def savetexttemp(self, fileName):
        textout = self.TemptextEdit.text()
        file = QtCore.QFile(fileName)
        if file.open(QtCore.QIODevice.WriteOnly):
            QtCore.QTextStream(file) << textout
        else:
            QtWidgets.QMessageBox.information(self.tempwizardPage,
                    'Unable to open file', file.errorString())
        os.chdir(str(self.path))

    def openscript(self):
        self.path = QtCore.QFileInfo(self.filename).path()

        # Get filename and show only .writer files
        (self.filename, _) = \
            QtWidgets.QFileDialog.getOpenFileName(self.wizardPage_3,
                'Open File', self.path,
                'Python Files (*.py *.pyc *.pyw)', '')

        if self.filename:
            with open(self.filename, 'r') as self.file:
                self.script_textEdit.setText(self.file.read())
        os.chdir(str(self.path))


    def savescript(self):
        self.path = QtCore.QFileInfo(self.filename).path()
        (self.filename, _) = \
            QtWidgets.QFileDialog.getSaveFileName(self.wizardPage_3, 'Save as'
                , self.path, 'Python Files (*.py *.pyc *.pyw)')
        if self.filename:
            self.savetextscript(self.filename)
        os.chdir(str(self.path))

    def savetextscript(self, fileName):
        textout = self.script_textEdit.text()
        file = QtCore.QFile(fileName)
        if file.open(QtCore.QIODevice.WriteOnly):
            QtCore.QTextStream(file) << textout
        else:
            QtWidgets.QMessageBox.information(self.wizardPage_3,
                    'Unable to open file', file.errorString())
        os.chdir(str(self.path))
      
class Ui_MainWindow(QtWidgets.QMainWindow):
    ARROW_MARKER_NUM = 8

    def __init__(self, parent=None):
        # Main windows
        super(Ui_MainWindow, self).__init__(parent=None)
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(640, 480)
        self.vindu = QtWidgets.QWidget(MainWindow)
        self.vindu.setStyleSheet("")
        self.vindu.setObjectName(_fromUtf8("vindu"))
        self.verticalLayout = PyQt5.QtWidgets.QVBoxLayout(self.vindu)
        
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(":/ico/python.png")), QtGui.QIcon.Normal, QtGui.QIcon.On)
        MainWindow.setWindowIcon(icon)
        
        self.verticalLayout.setContentsMargins(0,0,0,0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName(_fromUtf8('verticalLayout'))
        self.codebox = Qsci.QsciScintilla(self.vindu)
        self.codebox.setToolTip(_fromUtf8(""))
        self.codebox.setWhatsThis(_fromUtf8(""))
        self.codebox.setAutoFillBackground(False)
        self.codebox.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.codebox.setObjectName(_fromUtf8("codebox"))
        self.verticalLayout.addWidget(self.codebox)
        MainWindow.setCentralWidget(self.vindu)
        
        # cutsom config
        self.config_dir = os.path.join(os.path.expanduser("~"), ".python_editor")
        self.config_filename = os.path.join(self.config_dir, "config.dat")
        self.config = self.read_config() if self.read_config() else dict()
                
        # toolbar
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setAutoFillBackground(False)
        self.toolBar.setIconSize(QtCore.QSize(32, 32))
        self.toolBar.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        self.toolBar.setObjectName(_fromUtf8("toolBar2"))
        MainWindow.addToolBar(QtCore.Qt.LeftToolBarArea, self.toolBar)
        self.toolBar.addSeparator()

        #getting ready for debugger
        self.codebox.setMarginSensitivity(1, True)
        self.codebox.marginClicked.connect(self.on_margin_clicked)
        self.codebox.markerDefine(QsciScintilla.FullRectangle, self.ARROW_MARKER_NUM)
        self.codebox.setMarkerBackgroundColor(QColor("#ee1111"), self.ARROW_MARKER_NUM)
        
        self.action_icon = dict()
        
        #first action Newfile
        cur_icon = QtGui.QIcon(":/ico/new.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.newAction = QtWidgets.QAction(cur_icon,"New",self.toolBar)
        self.toolBar.newAction.setStatusTip("Clear TextBox or make new document.")
        self.toolBar.newAction.setShortcut("Ctrl+N")
        self.toolBar.newAction.triggered.connect(self.newfile)
        self.action_icon[self.toolBar.newAction] = (cur_icon, inv_icon)
        #second Action OpenFile
        cur_icon = QtGui.QIcon(":/ico/open.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.secondAction = QtWidgets.QAction(cur_icon,"Open",self.toolBar)
        self.toolBar.secondAction.setStatusTip("Create a new document from scratch.")
        self.toolBar.secondAction.setShortcut("Ctrl+O")
        self.toolBar.secondAction.triggered.connect(self.open)
        self.action_icon[self.toolBar.secondAction] = (cur_icon, inv_icon)
        # action 3 save file
        cur_icon = QtGui.QIcon(":/ico/save.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action3 = QtWidgets.QAction(cur_icon,"Save",self.toolBar)
        self.toolBar.Action3.setStatusTip("Save Your File.")
        self.toolBar.Action3.setShortcut("Ctrl+S")
        self.toolBar.Action3.triggered.connect(self.save_file)
        self.action_icon[self.toolBar.Action3] = (cur_icon, inv_icon)
        # action 3_1 save as file
        cur_icon = QtGui.QIcon(os.path.join(dn, "icons", "save_as.png"))
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action3_1 = QtWidgets.QAction(cur_icon,"Save As",self.toolBar)
        self.toolBar.Action3_1.setStatusTip("Save As New File.")
        self.toolBar.Action3_1.setShortcut("Ctrl+Shift+S")
        self.toolBar.Action3_1.triggered.connect(self.save_as_file)
        self.action_icon[self.toolBar.Action3_1] = (cur_icon, inv_icon)
        #action 4 run file
        cur_icon = QtGui.QIcon(":/ico/run32.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action4 = QtWidgets.QAction(cur_icon,"Run",self.toolBar)
        self.toolBar.Action4.setStatusTip("Run")
        self.toolBar.Action4.setShortcut("Ctrl+E")
        self.toolBar.Action4.triggered.connect(self.runto)
        self.action_icon[self.toolBar.Action4] = (cur_icon, inv_icon)
        #action 6 undo
        cur_icon = QtGui.QIcon(":/ico/undo.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action6 =  QtWidgets.QAction(cur_icon,"Undo",self.toolBar)
        self.toolBar.Action6.setStatusTip("Undo.")
        self.toolBar.Action6.setShortcut("Ctrl+Z")
        self.toolBar.Action6.triggered.connect(self.codebox.undo)
        self.action_icon[self.toolBar.Action6] = (cur_icon, inv_icon)
        #action 7 redo
        cur_icon = QtGui.QIcon(":/ico/redo.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action7 = QtWidgets.QAction(cur_icon,"Redo",self.toolBar)
        self.toolBar.Action7.setStatusTip("Redo.")
        self.toolBar.Action7.setShortcut("Ctrl+Shift+Z")
        self.toolBar.Action7.triggered.connect(self.codebox.redo)
        self.action_icon[self.toolBar.Action7] = (cur_icon, inv_icon)
        #action8 rerset Folding
        cur_icon = QtGui.QIcon(":/ico/align-justify.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action8 = QtWidgets.QAction(cur_icon,"Reset Folding",self.toolBar)
        self.toolBar.Action8.setStatusTip("Reset Folding.")
        self.toolBar.Action8.setShortcut("Ctrl+R")
        self.toolBar.Action8.triggered.connect(self.nofoldingl)
        self.action_icon[self.toolBar.Action8] = (cur_icon, inv_icon)
        #actions9 CircledTreeFoldStyle
        cur_icon = QtGui.QIcon(":/ico/bullet.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action9 = QtWidgets.QAction(cur_icon,"Circled Tree Folding",self.toolBar)
        self.toolBar.Action9.setStatusTip("Circled Tree Folding.")
        self.toolBar.Action9.setShortcut("Ctrl+C")
        self.toolBar.Action9.triggered.connect(self.Circledfold)
        self.action_icon[self.toolBar.Action9] = (cur_icon, inv_icon)
        #actions10 plainFoldStyle
        cur_icon = QtGui.QIcon(":/ico/number.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action10 = QtWidgets.QAction(cur_icon,"Plain Folding",self.toolBar)
        self.toolBar.Action10.setStatusTip("Plain Folding")
        self.toolBar.Action10.setShortcut("Ctrl+P")
        self.toolBar.Action10.triggered.connect(self.plainfold)
        self.action_icon[self.toolBar.Action10] = (cur_icon, inv_icon)
        #irc
        cur_icon = QtGui.QIcon(":/ico3/settings.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action12 = QtWidgets.QAction(cur_icon,"Open IDA Pro Python SDK",self.toolBar)
        self.toolBar.Action12.setStatusTip("IDA Pro Python SDK")
        self.toolBar.Action12.setShortcut("Ctrl+I")
        self.toolBar.Action12.triggered.connect(self.sdkopen)
        self.action_icon[self.toolBar.Action12] = (cur_icon, inv_icon)
        #github Python
        cur_icon = QtGui.QIcon(":/ico/github.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action14 = QtWidgets.QAction(cur_icon,"Open git python",self.toolBar)
        self.toolBar.Action14.setStatusTip("Open git python")
        self.toolBar.Action14.setShortcut("Ctrl+G")
        self.toolBar.Action14.triggered.connect(self.gitopen)
        self.action_icon[self.toolBar.Action14] = (cur_icon, inv_icon)
        #auther me :)
        cur_icon = QtGui.QIcon(":/ico/auth.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action15 = QtWidgets.QAction(cur_icon,"Author",self.toolBar)
        self.toolBar.Action15.setStatusTip("Author")
        self.toolBar.Action15.setShortcut("Ctrl+B")
        self.toolBar.Action15.triggered.connect(self.Author)
        self.action_icon[self.toolBar.Action15] = (cur_icon, inv_icon)
        #toggle off code regonision
        cur_icon = QtGui.QIcon(":/ico2/pythonminus.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action16 = QtWidgets.QAction(cur_icon,"Disable Code autocomplete",self.toolBar)
        self.toolBar.Action16.setStatusTip("Disable Code autocomplete")
        self.toolBar.Action16.setShortcut("Alt+D")
        self.toolBar.Action16.triggered.connect(self.Diablecode)
        self.action_icon[self.toolBar.Action16] = (cur_icon, inv_icon)
        #toogle on
        cur_icon = QtGui.QIcon(":/ico2/pypluss.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action17 = QtWidgets.QAction(cur_icon,"Enable Code autocomplete",self.toolBar)
        self.toolBar.Action17.setStatusTip("Enable Code autocomplete")
        self.toolBar.Action17.setShortcut("Alt+E")
        self.toolBar.Action17.triggered.connect(self.Reiablecode)
        self.action_icon[self.toolBar.Action17] = (cur_icon, inv_icon)
        # zoom in
        cur_icon = QtGui.QIcon(":/ico3/in.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action18 = QtWidgets.QAction(cur_icon,"Zoom In",self.toolBar)
        self.toolBar.Action18.setStatusTip("Zoom In")
        self.toolBar.Action18.setShortcut("CTRL+SHIFT++")
        self.toolBar.Action18.triggered.connect(self.udder)
        self.action_icon[self.toolBar.Action18] = (cur_icon, inv_icon)
        #zoom out
        cur_icon = QtGui.QIcon(":/ico3/out.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action19 = QtWidgets.QAction(cur_icon,"Zoom Out",self.toolBar)
        self.toolBar.Action19.setStatusTip("Zoom Out")
        self.toolBar.Action19.setShortcut("CTRL+SHIFT+-")
        self.toolBar.Action19.triggered.connect(self.odder)
        self.action_icon[self.toolBar.Action19] = (cur_icon, inv_icon)
        # profile
        cur_icon = QtGui.QIcon(":/ico3/10.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action20 = QtWidgets.QAction(cur_icon,"Profile Code",self.toolBar)
        self.toolBar.Action20.setStatusTip("Profile Code")
        self.toolBar.Action20.setShortcut("CTRL+SHIFT+E")
        self.toolBar.Action20.triggered.connect(self.runtoprob)
        self.action_icon[self.toolBar.Action20] = (cur_icon, inv_icon)
        # fonts
        cur_icon = QtGui.QIcon(":/ico4/font.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action21 = QtWidgets.QAction(cur_icon, "Fonts", self.toolBar)
        self.toolBar.Action21.setStatusTip("Fonts")
        self.toolBar.Action21.setShortcut("Ctrl+F")
        self.toolBar.Action21.triggered.connect(self.font_choice)
        self.action_icon[self.toolBar.Action21] = (cur_icon, inv_icon)
        # PLUGINS HERE WE GO
        cur_icon = QtGui.QIcon(":/ico5/plugin.png")
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action22 = QtWidgets.QAction(cur_icon,"Plugin",self.toolBar)
        self.toolBar.Action22.setStatusTip("Make plugin")
        self.toolBar.Action22.setShortcut("")
        self.toolBar.Action22.triggered.connect(self.plugin_make)
        self.action_icon[self.toolBar.Action22] = (cur_icon, inv_icon)
        # invert theme
        cur_icon = QtGui.QIcon(os.path.join(dn, "icons", "invert.png"))
        inv_icon = self.invert_icon(cur_icon)
        self.toolBar.Action23 = QtWidgets.QAction(cur_icon,"Switch theme",self.toolBar)
        self.toolBar.Action23.setStatusTip("Switch Light/Dark theme")
        self.toolBar.Action23.setShortcut("")
        self.toolBar.Action23.triggered.connect(self.switch_theme)
        self.action_icon[self.toolBar.Action23] = (cur_icon, inv_icon)
        
        # script settings
        self.scriptfile = self.codebox.text()
        self.filename = ""

        #actions
        self.toolBar.addAction(self.toolBar.newAction)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.secondAction)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action3)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action3_1)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action4)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action6)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action7)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action8)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action9)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action10)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action21)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action12)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action14)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action15)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action16)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action17)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action18)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action19)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action20)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action21)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action22)
        self.toolBar.addSeparator()
        self.toolBar.addAction(self.toolBar.Action23)

        self.default_font = QFont()
        self.default_font.setFamily('Consolas')
        self.default_font.setFixedPitch(True)
        self.default_font.setPointSize(12)
        
        self.skrift = self.make_font(self.get_config('font')) if self.get_config('font') else self.default_font
        self.codebox.setFont(self.skrift)
        
        #python style
        self.lexer = QsciLexerPython(self.codebox)
        self.lexer.setFont(self.skrift)
        #api test not working
        api = Qsci.QsciAPIs(self.lexer)
        API_FILE =  os.path.join(dn, 'python.api')
        API_FILE2 = os.path.join(dn, 'idc.api')
        API_FILE3 = os.path.join(dn, 'idaapi.api')
        API_FILE4 = os.path.join(dn, 'idautils.api')
        api.load(API_FILE)
        api.load(API_FILE2)
        api.load(API_FILE3)
        api.load(API_FILE4)

        api.prepare()
        self.codebox.setAutoCompletionThreshold(1)
        self.codebox.setAutoCompletionSource(Qsci.QsciScintilla.AcsAPIs)
        self.lexer.setDefaultFont(self.skrift)
        self.codebox.setLexer(self.lexer)
        self.codebox.SendScintilla(QsciScintilla.SCI_STYLESETFONT, 1, b'Consolas')

        #line numbers
        fontmetrics = QFontMetrics(self.skrift)
        self.codebox.setMarginsFont(self.skrift)
        self.codebox.setMarginWidth(0, fontmetrics.width("00000") + 6)
        self.codebox.setIndentationsUseTabs(False)
        self.codebox.setTabWidth(4)

        #brace
        self.codebox.setBraceMatching(QsciScintilla.SloppyBraceMatch)

        #auto line tab =4
        self.codebox.setAutoIndent(True)

        #scrollbar
        self.codebox.SendScintilla(QsciScintilla.SCI_SETHSCROLLBAR, 1)
        
        # set theme
        self.dark_theme = True if self.get_config('dark_theme') else False
        self.set_theme(self.dark_theme)

        self.retranslateUi(MainWindow)

        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    
    def invert_icon(self, cur_icon):
        pixmap = cur_icon.pixmap(cur_icon.actualSize(QtCore.QSize(32, 32)));
        img = pixmap.toImage()
        img.invertPixels()
        pixmap = QtGui.QPixmap.fromImage(img)
        return QtGui.QIcon(pixmap)
    
    def read_config(self):
        if os.path.isfile(self.config_filename):
            with open(self.config_filename, "rb") as f:
                return pickle.load(f) 
        else:
            return None
    
    def write_config(self):
        def mkdir_p(path):
            import errno
            try:
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise
        mkdir_p(self.config_dir)
        with open(self.config_filename, "wb") as f:
            pickle.dump(self.config, f)
    
    def make_font(self, attr):
        """ attr = (family, fontsize)"""
        family, font_size = attr
        ret = QFont()
        ret.setFamily(family)
        ret.setFixedPitch(True)
        ret.setPointSize(font_size)
        return ret
    
    def get_config(self, key):
        if key in self.config and self.config[key] != None:
            return self.config[key]
        else:
            return None
    
    def switch_theme(self):
        self.dark_theme = False if self.dark_theme else True # switch theme
        self.set_theme(self.dark_theme)
        self.config['dark_theme'] = self.dark_theme
        self.write_config()
        print("Theme update success")
        
    def set_theme(self, dark=False):
        """ swith dark / light theme """
        # self.vindu
        # self.toolBar
        # codebox lexer
        # codebox line number margin
        cur_style_sheet = qdarkstyle.load_stylesheet_pyqt5() if dark else ""
        # switch theme
        self.vindu.setStyleSheet(cur_style_sheet)
        self.toolBar.setStyleSheet(cur_style_sheet)
        # switch icon
        icon_id = 1 if dark else 0
        for k, v in self.action_icon.items():
            cur_icon = v[icon_id]
            k.setIcon(cur_icon)
        # codebox lexer
        if dark:
            self.set_dark_lexer()
        else:
            self.set_light_lexer()
        # codebox line number margin
        f, b = (QColor('white'), QColor("#2E3336")) if dark else (QColor('black'), QColor("#e0e0e0"))
        self.codebox.setMarginsForegroundColor(f)
        self.codebox.setMarginsBackgroundColor(b)
    
    def set_lexer_attr(self, attr, color, paper):
        self.lexer.setColor(color, attr)
        self.lexer.setPaper(paper, attr)
    
    def set_dark_lexer(self):
        paper = QColor("#3c3c3c")
        # bg
        self.lexer.setDefaultPaper(paper)
        # cursor style
        self.codebox.setCaretForegroundColor(QColor('gray'))
        self.codebox.setCaretLineVisible(True)
        self.codebox.setCaretLineBackgroundColor(QColor("#1f1f2e"))
        # brace matched style
        self.codebox.setMatchedBraceForegroundColor(QColor("orange"))
        self.codebox.setMatchedBraceBackgroundColor(paper)
        self.codebox.setUnmatchedBraceForegroundColor(QColor("red"))
        self.codebox.setUnmatchedBraceBackgroundColor(paper)
        # code style
        self.set_lexer_attr(QsciLexerPython.Default, QColor('white'), paper)
        self.set_lexer_attr(QsciLexerPython.Comment, QColor('lightblue'), paper)
        self.set_lexer_attr(QsciLexerPython.Number, QColor('white'), paper)
        self.set_lexer_attr(QsciLexerPython.DoubleQuotedString, QColor('yellow'), paper)
        self.set_lexer_attr(QsciLexerPython.SingleQuotedString, QColor('yellow'), paper)
        self.set_lexer_attr(QsciLexerPython.Keyword, QColor('lightgreen'), paper)
        self.set_lexer_attr(QsciLexerPython.TripleSingleQuotedString, QColor('yellow'), paper)
        self.set_lexer_attr(QsciLexerPython.TripleDoubleQuotedString, QColor('lightblue'), paper)
        self.set_lexer_attr(QsciLexerPython.ClassName, QColor('cyan'), paper)
        self.set_lexer_attr(QsciLexerPython.FunctionMethodName, QColor('cyan'), paper)
        self.set_lexer_attr(QsciLexerPython.Operator, QColor('white'), paper)
        self.set_lexer_attr(QsciLexerPython.Identifier, QColor('white'), paper)
        self.set_lexer_attr(QsciLexerPython.CommentBlock, QColor('lightblue'), paper)
        self.set_lexer_attr(QsciLexerPython.UnclosedString, QColor('#666'), paper)
        self.set_lexer_attr(QsciLexerPython.HighlightedIdentifier, QColor('#ffffff'), paper)
        self.set_lexer_attr(QsciLexerPython.Decorator, QColor('#cccccc'), paper)
       
    def set_light_lexer(self):
        paper = QColor("white")
        # bg
        self.lexer.setDefaultPaper(paper)
        # cursor style
        self.codebox.setCaretForegroundColor(QColor('black'))
        self.codebox.setCaretLineVisible(True)
        self.codebox.setCaretLineBackgroundColor(QColor("#e0ccff"))
        # brace matched style
        self.codebox.setMatchedBraceForegroundColor(QColor("orange"))
        self.codebox.setMatchedBraceBackgroundColor(QColor("#F7F8E0"))
        self.codebox.setUnmatchedBraceForegroundColor(QColor("red"))
        self.codebox.setUnmatchedBraceBackgroundColor(QColor("#F7F8E0"))
        # code style
        self.set_lexer_attr(QsciLexerPython.Default, QColor('black'), paper)
        self.set_lexer_attr(QsciLexerPython.Comment, QColor('gray'), paper)
        self.set_lexer_attr(QsciLexerPython.Number, QColor('black'), paper)
        self.set_lexer_attr(QsciLexerPython.DoubleQuotedString, QColor('#800000'), paper)
        self.set_lexer_attr(QsciLexerPython.SingleQuotedString, QColor('#800000'), paper)
        self.set_lexer_attr(QsciLexerPython.Keyword, QColor('#008080'), paper)
        self.set_lexer_attr(QsciLexerPython.TripleSingleQuotedString, QColor('#060'), paper)
        self.set_lexer_attr(QsciLexerPython.TripleDoubleQuotedString, QColor('#060'), paper)
        self.set_lexer_attr(QsciLexerPython.ClassName, QColor('#0000a0'), paper)
        self.set_lexer_attr(QsciLexerPython.FunctionMethodName, QColor('#0000a0'), paper)
        self.set_lexer_attr(QsciLexerPython.Operator, QColor('black'), paper)
        self.set_lexer_attr(QsciLexerPython.Identifier, QColor('black'), paper)
        self.set_lexer_attr(QsciLexerPython.CommentBlock, QColor('gray'), paper)
        self.set_lexer_attr(QsciLexerPython.UnclosedString, QColor('#FFDDDD'), paper)
        self.set_lexer_attr(QsciLexerPython.HighlightedIdentifier, QColor('#0000a0'), paper)
        self.set_lexer_attr(QsciLexerPython.Decorator, QColor('#cc6600'), paper)    

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("MainWindow", "IDA Pro Python Script Editor", None))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar", None))

    def plugin_make(self):
        Wizard.show()

    def sendgrapped(self):
        helloclass = Ui_Wizard()
        self.bsout = self.codebox.text()
        helloclass.script_textEdit.setText(self.bsout)

    def udder(self):
        self.codebox.zoomIn()

    def odder(self):
        self.codebox.zoomOut()

    def ask_save(self, msg):
        # need to save ?
        if not self.filename and not self.codebox.text(): # no filename + no text = ain't save shit
            return 0
        
        if self.filename:
            with open(self.filename, 'rb') as f:
                if f.read() == self.codebox.text(): # don't need to save
                    return 0
        
        buttonReply = QMessageBox.question(self, 'Save the none-save work ?', msg, QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.Cancel)
        if buttonReply == QMessageBox.Yes:
            return 1
        elif buttonReply == QMessageBox.No:
            return 0
        else: # cancel or x 
            return 2    
      
    def newfile(self):
        resp = self.ask_save("Save before open a new file ?")
        if resp == 1: # yes save file
            self.save_file()
        elif resp == 2: # cancel or x
            return
            
        self.codebox.clear()
        self.filename = ""

    def open(self):
        resp = self.ask_save("Save before open an existed file ?")
        if resp == 1: # yes save file
            self.save_file()
        elif resp == 2: # cancel or x
            return
                
        self.path = QtCore.QFileInfo(self.filename).path()
        old_filename = self.filename
        # Get filename and show only .writer files
        (self.filename, _) = \
            QtWidgets.QFileDialog.getOpenFileName(self.vindu,
                'Open File', self.path,
                'Python Files (*.py *.pyc *.pyw)', '')

        if self.filename:
            with open(self.filename, 'r') as self.file:
                self.codebox.setText(self.file.read())
        else:
            self.filename = old_filename
        os.chdir(str(self.path))

    def close(self, event):
        resp = self.ask_save("Save before exit ?")
        if resp == 1: # yes save file
            self.save_file()
        elif resp == 2: # cancel or x
            event.ignore()
            return
        
        event.accept()
        os.chdir(dn)
        
    def save_as_file(self):
        self.path = QtCore.QFileInfo(self.filename).path()
        old_filename = self.filename
        (self.filename, _) = \
            QtWidgets.QFileDialog.getSaveFileName(self.vindu, 'Save as'
                , self.path, 'Python Files (*.py *.pyc *.pyw)')
        if self.filename:
            self.save_file()
        else:
            self.filename = old_filename
        os.chdir(str(self.path))

    def save_file(self):
        if not self.filename:
            self.save_as_file()
            return
        
        textout = self.codebox.text()
        file = QtCore.QFile(self.filename)
        if file.open(QtCore.QIODevice.WriteOnly):
            QtCore.QTextStream(file) << textout
            print("Save to {}".format(self.filename))
        else:
            QtWidgets.QMessageBox.information(self.vindu,
                    'Unable to open file', file.errorString())
        os.chdir(str(self.path))

    def runto(self):
        import traceback
        class InterpreterError(Exception): pass
        
        self.path = QtCore.QFileInfo(self.filename).path()
        g = globals()
        os.chdir(str(self.path))
        script = str(self.codebox.text())
        
        try:
            os.chdir(str(self.path))
            os.path.join(os.path.expanduser('~'), os.path.expandvars(str(self.path)))
            sys.path.insert(0, str(self.path))
            exec(script, g)
        except SyntaxError as err:
            error_class = err.__class__.__name__
            detail = err.args[0]
            line_number = err.lineno
        except Exception as err:
            error_class = err.__class__.__name__
            detail = err.args[0]
            cl, exc, tb = sys.exc_info()
            line_number = traceback.extract_tb(tb)[-1][1]
        else:
            return
        raise InterpreterError("%s at line %d of source string: %s" % (error_class, line_number, detail))

    def runtoprob(self):
        try:
            self.path = QtCore.QFileInfo(self.filename).path()
            self.path = QtCore.QFileInfo(self.filename).path()
            g = globals()
            os.chdir(str(self.path))
            script = str(self.codebox.text())
            import cProfile
            cProfile.run(script)
        except Exception as e:
            print(e.__doc__)
            print(e.message)
        else:
            import cProfile
            cProfile.run(script)

    def Diablecode(self):
        self.codebox.setAutoCompletionSource(Qsci.QsciScintilla.AcsNone)

    def Reiablecode(self):
        self.codebox.setAutoCompletionSource(Qsci.QsciScintilla.AcsAPIs)

    def nofoldingl(self):
        self.codebox.setFolding(QsciScintilla.NoFoldStyle)

    def Circledfold(self):
        self.codebox.setFolding(QsciScintilla.CircledTreeFoldStyle)

    def plainfold(self):
        self.codebox.setFolding(QsciScintilla.PlainFoldStyle)

    def sdkopen(self):
        import webbrowser
        webbrowser.open('https://www.hex-rays.com/products/ida/support/idapython_docs/')

    def gitopen(self):
        import webbrowser
        webbrowser.open('https://github.com/idapython/src')

    def Author(self):
        import webbrowser
        webbrowser.open('https://github.com/techbliss')

    def font_choice(self):
        self.lbl = self.lexer
        font, ok = QtWidgets.QFontDialog.getFont(self.skrift)
        if ok:
            self.skrift = font
            self.codebox.setFont(self.skrift)
            self.codebox.setMarginsFont(self.skrift)
            self.lbl.setFont(self.skrift)
            self.config['font'] = (font.family(), font.pointSize())
            self.write_config()
            print("Font update success")

    def on_margin_clicked(self, nmargin, nline, modifiers):
        # Toggle marker for the line the margin was clicked on
        if self.codebox.markersAtLine(nline) != 0:
            self.codebox.markerDelete(nline, self.ARROW_MARKER_NUM)
        else:
            self.codebox.markerAdd(nline, self.ARROW_MARKER_NUM)

# main function            
Wizard = QtWidgets.QWizard()
MainWindow = QtWidgets.QMainWindow()
ui = Ui_MainWindow()
messageformForm = QtWidgets.QWidget()
ui2 = Ui_Wizard()
ui3 = Ui_messageformForm()
ui3.setupUi1(messageformForm)
MainWindow.resize(1000, 600)
MainWindow.closeEvent = ui.close
MainWindow.show()

