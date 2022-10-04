#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 1:
    - Familiarize with Steganography and design a simple LSB steganography application.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
stego.py
    - Contains the general functionality like GUI, checking file sizes, file formats, etc.
----------------------------------------------------------------------------------------------------
"""

import PyQt5
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import QFileDialog, QDesktopWidget
import image, utils, encryption


def start_program():
    encryption.generate_key()
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    ui.set_button_functions()
    MainWindow.show()
    # Run the App
    app.exec_()


def file_picker(label):
    # Open File Dialog, returns tuple (file name, type of file)
    fname = QFileDialog.getOpenFileName(caption="Open File", directory="", filter="All Files (*);;BMP (*.bmp)")
    if fname:
        label.setText(str(fname[0]))
        label.setAlignment(QtCore.Qt.AlignRight)

    return fname


def directory_picker(label):
    # Open File Dialog, returns tuple (file name, type of file)
    fname = QFileDialog.getExistingDirectory(caption="Open Folder")
    if fname:
        label.setText(str(fname))
        label.setAlignment(QtCore.Qt.AlignRight)

    return fname


class Ui_MainWindow(object):
    def start_embed(self):
        # Check if any fields are empty
        if self.embed_cover_image_label.text() == "No file selected." \
                or len(self.embed_cover_image_label.text()) < 1:
            self.embed_verify_label.setText("Event Log:\n Error, Missing cover image.")
            return
        elif self.embed_secret_data_label.text() == "No file selected." \
                or len(self.embed_secret_data_label.text()) < 1:
            self.embed_verify_label.setText("Event Log:\n Error, Missing secret file.")
            return
        elif self.embed_destination_label.text() == "No destination." \
                or len(self.embed_destination_label.text()) < 1:
            self.embed_verify_label.setText("Event Log:\n Error, Missing destination folder.")
            return
        elif self.embed_lsb_lineedit.text() == '0' or self.embed_lsb_lineedit.text() == '9':
            self.embed_verify_label.setText("Event Log:\n Error, LSB must be 1 to 8.")
            return


        # Cover image process.
        image_path = self.embed_cover_image_label.text()
        cover_ext = image_path.split("/")[-1]
        if cover_ext.split(".")[-1].lower() != "bmp":
            self.embed_verify_label.setText("Event Log:\n Error, Cover image must be a .bmp file.")
            return
        img_array = image.read_image(image_path)

        # Secret file process.
        secret_path = self.embed_secret_data_label.text()
        filename_ext = secret_path.split("/")[-1]
        print(filename_ext)
        with open(secret_path, "rb") as f:
            data = f.read()

        # Get LSB value
        lsb = int(self.embed_lsb_lineedit.text())

        # Check cover image is .bmp and cover image large enough to hide data.
        secret_bitstring = utils.data_and_filename_to_binary(data, filename_ext)
        if len(secret_bitstring) > img_array.size * lsb:
            print("Error, cover image too small to embed secret data. "
                  "Use bigger cover image or smaller secret file.")
            self.embed_verify_label.setText("Event Log:\nError, cover image too small to embed secret data."
                                            "Use bigger cover image or smaller secret file.")
            return

        # Destination and output process.
        destination_dir = self.embed_destination_label.text()
        output_path = f'{destination_dir}/[Stega]{cover_ext}'


        # Save the Steganography image at destination folder.
        stega_img_array = utils.embed(img_array, data, filename_ext, lsb=lsb)
        image.save_image(stega_img_array, output_path)
        print(f"Stega Image Saved to: {output_path}")
        self.embed_verify_label.setText(f"Event Log:\nSuccess, Stega image saved to {output_path}.")

    def start_extract(self):
        # Check if any fields are empty
        if self.extract_image_label.text() == "No image." or len(self.extract_image_label.text()) < 1:
            self.extract_verify_label.setText("Event Log:\n Error, Missing image.")
            return
        elif self.extract_destination_label.text() == "No destination." \
                or len(self.extract_destination_label.text()) < 1:
            self.extract_verify_label.setText("Event Log:\n Error, Missing destination folder.")
            return
        elif self.extract_lsb_lineedit.text() == '0' or self.extract_lsb_lineedit.text() == '9':
            self.extract_verify_label.setText("Event Log:\n Error, LSB must be 1 to 8.")
            return

        # Secret file process.
        image_path = self.extract_image_label.text()
        cover_ext = image_path.split("/")[-1].split(".")[-1].lower()
        if cover_ext != "bmp":
            self.extract_verify_label.setText("Event Log:\n Error, Image must be a .bmp file.")
            return
        img_array = image.read_image(image_path)

        # Get LSB value
        lsb = int(self.extract_lsb_lineedit.text())

        # Extract the image
        try:
            filename, byte_data = utils.extract(img_array, lsb=lsb)
        except ValueError:
            self.extract_verify_label.setText("Event Log:\n Error, unable to extract steganography from image. "
                                              "Image may not have steganography, or has been modified after "
                                              "embedding.")
            return

        # Destination and Secret Output process.
        destination_dir = self.extract_destination_label.text()
        output_path = f'{destination_dir}/[Secret]{filename.decode("utf-8")}'

        with open(output_path, "wb") as f2:
            f2.write(byte_data)
            print(f"Extracted Data Saved to: {output_path}")
            self.extract_verify_label.setText(f"Event Log:\nSuccess, Secret data saved to {output_path}.")

    def select_embed_cover_image(self):
        file_picker(self.embed_cover_image_label)
        # image_path = self.embed_cover_image_label.text()
        # cover_ext = image_path.split("/")[-1].split(".")[-1]
        # if cover_ext.lower() != "bmp":
        #     self.embed_verify_label.setText("Event Log:\n Error, Cover image must be .bmp file.")

    def select_embed_file(self):
        file_picker(self.embed_secret_data_label)

    def select_embed_destination(self):
        directory_picker(self.embed_destination_label)

    def select_extract_image(self):
        file_picker(self.extract_image_label)

    def select_extract_destination(self):
        directory_picker(self.extract_destination_label)

    def set_button_functions(self):
        self.embed_cover_btn.clicked.connect(self.select_embed_cover_image)
        self.embed_secret_btn.clicked.connect(self.select_embed_file)
        self.embed_destination_btn.clicked.connect(self.select_embed_destination)
        self.start_embed_btn.clicked.connect(self.start_embed)
        self.extract_image_btn.clicked.connect(self.select_extract_image)
        self.extract_destination_btn.clicked.connect(self.select_extract_destination)
        self.start_extract_btn.clicked.connect(self.start_extract)

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(521, 415)

        # Move GUI to center of screen.
        window = MainWindow.frameGeometry()
        screen_center = QDesktopWidget().availableGeometry().center()
        window.moveCenter(screen_center)
        MainWindow.move(window.topLeft())

        # Main Window.
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # Create 2 Tabs.
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 521, 391))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.tabWidget.addTab(self.tab_2, "")

        # Create Embed Instructions Label.
        self.embed_instructions_label = QtWidgets.QLabel(self.tab)
        self.embed_instructions_label.setGeometry(QtCore.QRect(10, 20, 181, 91))
        self.embed_instructions_label.setObjectName("embed_instructions_label")

        # Create verify info label.
        self.embed_verify_label = QtWidgets.QLabel(self.tab)
        self.embed_verify_label.setGeometry(QtCore.QRect(10, 250, 350, 68))
        self.embed_verify_label.setObjectName("embed_verify_label")
        self.embed_verify_label.setWordWrap(True)
        # Create verify info label.
        self.extract_verify_label = QtWidgets.QLabel(self.tab_2)
        self.extract_verify_label.setGeometry(QtCore.QRect(10, 250, 350, 68))
        self.extract_verify_label.setObjectName("extract_verify_label")
        self.extract_verify_label.setWordWrap(True)

        # Embed section, select COVER IMAGE button and label
        self.embed_cover_btn = QtWidgets.QPushButton(self.tab)
        self.embed_cover_btn.setGeometry(QtCore.QRect(10, 150, 151, 34))
        self.embed_cover_btn.setObjectName("embed_cover_btn")
        self.embed_cover_image_label = QtWidgets.QLabel(self.tab)
        self.embed_cover_image_label.setGeometry(QtCore.QRect(10, 190, 161, 20))
        self.embed_cover_image_label.setObjectName("embed_cover_image_label")

        # Embed section, select SECRET DATA button and label
        self.embed_secret_btn = QtWidgets.QPushButton(self.tab)
        self.embed_secret_btn.setGeometry(QtCore.QRect(180, 150, 151, 34))
        self.embed_secret_btn.setObjectName("embed_secret_btn")
        self.embed_secret_data_label = QtWidgets.QLabel(self.tab)
        self.embed_secret_data_label.setGeometry(QtCore.QRect(180, 190, 151, 20))
        self.embed_secret_data_label.setObjectName("embed_secret_data_label")

        # Embed section, select OUTPUT DESTINATION button and label
        self.embed_destination_btn = QtWidgets.QPushButton(self.tab)
        self.embed_destination_btn.setGeometry(QtCore.QRect(350, 150, 151, 34))
        self.embed_destination_btn.setObjectName("embed_destination_btn")
        self.embed_destination_label = QtWidgets.QLabel(self.tab)
        self.embed_destination_label.setGeometry(QtCore.QRect(350, 190, 151, 20))
        self.embed_destination_label.setObjectName("embed_destination_label")

        # Embed LSB section
        self.embed_lsb_label = QtWidgets.QLabel(self.tab)
        self.embed_lsb_label.setGeometry(QtCore.QRect(380, 240, 60, 20))
        self.embed_lsb_label.setObjectName("embed_lsb_label")
        self.embed_lsb_label.setText("LSB (1-8):")
        self.embed_lsb_lineedit = QtWidgets.QLineEdit(self.tab)
        self.embed_lsb_lineedit.setGeometry(QtCore.QRect(440, 240, 40, 20))
        self.embed_lsb_lineedit.setObjectName("embed_lsb_lineedit")
        self.embed_lsb_lineedit.setText("1")
        self.embed_lsb_lineedit.setValidator(QIntValidator())
        self.embed_lsb_lineedit.setMaxLength(1)

        # Extract LSB section
        self.extract_lsb_label = QtWidgets.QLabel(self.tab_2)
        self.extract_lsb_label.setGeometry(QtCore.QRect(380, 240, 60, 20))
        self.extract_lsb_label.setObjectName("extract_lsb_label")
        self.extract_lsb_label.setText("LSB (1-8):")
        self.extract_lsb_lineedit = QtWidgets.QLineEdit(self.tab_2)
        self.extract_lsb_lineedit.setGeometry(QtCore.QRect(440, 240, 40, 20))
        self.extract_lsb_lineedit.setObjectName("extract_lsb_lineedit")
        self.extract_lsb_lineedit.setText("1")
        self.extract_lsb_lineedit.setValidator(QIntValidator())
        self.extract_lsb_lineedit.setMaxLength(1)

        # Embed section, START EMBEDDING button
        self.start_embed_btn = QtWidgets.QPushButton(self.tab)
        self.start_embed_btn.setGeometry(QtCore.QRect(380, 290, 111, 34))
        self.start_embed_btn.setObjectName("start_embed_btn")

        # Create Extract Instructions Label.
        self.extract_instructions_label = QtWidgets.QLabel(self.tab_2)
        self.extract_instructions_label.setGeometry(QtCore.QRect(10, 20, 201, 71))
        self.extract_instructions_label.setObjectName("extract_instructions_label")

        # Extract section, select STEGANOGRAPHY IMAGE button and label
        self.extract_image_btn = QtWidgets.QPushButton(self.tab_2)
        self.extract_image_btn.setGeometry(QtCore.QRect(10, 150, 151, 34))
        self.extract_image_btn.setObjectName("extract_image_btn")
        self.extract_image_label = QtWidgets.QLabel(self.tab_2)
        self.extract_image_label.setGeometry(QtCore.QRect(10, 190, 161, 20))
        self.extract_image_label.setObjectName("extract_image_label")

        # Extract section, select OUTPUT DESTINATION button and label
        self.extract_destination_label = QtWidgets.QLabel(self.tab_2)
        self.extract_destination_label.setGeometry(QtCore.QRect(180, 190, 151, 20))
        self.extract_destination_label.setObjectName("extract_destination_label")
        self.extract_destination_btn = QtWidgets.QPushButton(self.tab_2)
        self.extract_destination_btn.setGeometry(QtCore.QRect(180, 150, 151, 34))
        self.extract_destination_btn.setObjectName("extract_destination_btn")

        # Embed section, START EXTRACTING button
        self.start_extract_btn = QtWidgets.QPushButton(self.tab_2)
        self.start_extract_btn.setGeometry(QtCore.QRect(380, 290, 111, 34))
        self.start_extract_btn.setObjectName("start_extract_btn")

        # Create Menubar and Statusbar
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 521, 30))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.embed_cover_btn.setText(_translate("MainWindow", "Select cover file"))

        # Embed tab instructions.
        self.embed_instructions_label.setText(_translate("MainWindow", "Embed Instructions:\n"
                                                         "1. Select BMP cover image.\n"
                                                         "2. Select secret data file.\n"
                                                         "3. Select output destination.\n"
                                                         "4. Click Start Embed."))
        self.embed_verify_label.setText(_translate("MainWindow", ""))
        self.embed_cover_image_label.setText(_translate("MainWindow", "No file selected."))
        self.embed_secret_data_label.setText(_translate("MainWindow", "No file selected."))
        self.embed_destination_label.setText(_translate("MainWindow", "No destination."))
        self.embed_secret_btn.setText(_translate("MainWindow", "Select secret file"))
        self.embed_destination_btn.setText(_translate("MainWindow", "Select destination"))
        self.start_embed_btn.setText(_translate("MainWindow", "Start Embed"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Embed"))

        # Extract tab instructions
        self.extract_instructions_label.setText(_translate("MainWindow", "Extract Intructions:\n"
                                                           "1. Select image to extract.\n"
                                                           "2. Select output destination.\n"
                                                           "3. Click Start Extract."))
        self.extract_image_btn.setText(_translate("MainWindow", "Select Image"))
        self.extract_destination_btn.setText(_translate("MainWindow", "Select destination"))
        self.extract_image_label.setText(_translate("MainWindow", "No image."))
        self.extract_destination_label.setText(_translate("MainWindow", "No destination."))
        self.start_extract_btn.setText(_translate("MainWindow", "Start Extract"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Extract"))


if __name__ == "__main__":
    try:
        start_program()
    finally:
        exit()
    # except KeyboardInterrupt as e:
    #     print("KeyboardInterrupt Shutdown")
    #     exit()
