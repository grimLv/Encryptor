import sys
import os
from PyQt5.QtWidgets import QApplication, QFileDialog, QVBoxLayout, QPushButton, QLabel, QLineEdit, QWidget, QMessageBox
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet
import struct


class EncryptTool(QWidget):
    HEADER = b"ENCRYPTED_FILE"  # 标记文件已加密

    def __init__(self):
        super().__init__()
        self.setWindowTitle("文件加密工具")
        self.setGeometry(100, 100, 400, 200)

        self.init_ui()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def init_ui(self):
        layout = QVBoxLayout()

        # 显示选择的路径
        self.path_label = QLabel("选择文件或文件夹路径:")
        layout.addWidget(self.path_label)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("选择文件或文件夹路径...")
        layout.addWidget(self.path_input)

        # 浏览按钮
        browse_button = QPushButton("浏览")
        browse_button.clicked.connect(self.browse_path)
        layout.addWidget(browse_button)

        # 加密按钮
        encrypt_button = QPushButton("加密")
        encrypt_button.clicked.connect(self.encrypt_file_or_folder)
        layout.addWidget(encrypt_button)

        # 解密按钮
        decrypt_button = QPushButton("解密")
        decrypt_button.clicked.connect(self.decrypt_file_or_folder)
        layout.addWidget(decrypt_button)

        self.setLayout(layout)

    def browse_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")  # 默认选择文件
        if not path:
            path = QFileDialog.getExistingDirectory(self, "选择文件夹")  # 如果没选文件则尝试选择文件夹
        if path:
            self.path_input.setText(path)

    def encrypt_file_or_folder(self):
        path = self.path_input.text()
        if not path:
            QMessageBox.warning(self, "错误", "请先选择文件或文件夹路径！")
            return

        if os.path.isfile(path):
            self.encrypt_file(path)
        elif os.path.isdir(path):
            self.encrypt_folder(path)
        else:
            QMessageBox.warning(self, "错误", "路径无效！")

    def encrypt_file(self, filepath):
        try:
            with open(filepath, "rb") as file:
                data = file.read()

            # 检查文件是否已加密
            if data.startswith(self.HEADER):
                QMessageBox.warning(self, "错误", "文件已加密！")
                return

            encrypted_data = self.HEADER + self.cipher.encrypt(data)

            with open(filepath, "wb") as file:
                file.write(encrypted_data)

            QMessageBox.information(self, "成功", f"文件已加密: {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {e}")

    def encrypt_folder(self, folderpath):
        try:
            for root, dirs, files in os.walk(folderpath):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.encrypt_file(filepath)
            QMessageBox.information(self, "成功", f"文件夹已加密: {folderpath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {e}")

    def decrypt_file_or_folder(self):
        path = self.path_input.text()
        if not path:
            QMessageBox.warning(self, "错误", "请先选择文件或文件夹路径！")
            return

        if os.path.isfile(path):
            self.decrypt_file(path)
        elif os.path.isdir(path):
            self.decrypt_folder(path)
        else:
            QMessageBox.warning(self, "错误", "路径无效！")

    def decrypt_file(self, filepath):
        try:
            with open(filepath, "rb") as file:
                data = file.read()

            # 检查文件是否已加密
            if not data.startswith(self.HEADER):
                QMessageBox.warning(self, "错误", "文件不是加密文件！")
                return

            encrypted_data = data[len(self.HEADER) :]
            decrypted_data = self.cipher.decrypt(encrypted_data)

            with open(filepath, "wb") as file:
                file.write(decrypted_data)

            QMessageBox.information(self, "成功", f"文件已解密: {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {e}")

    def decrypt_folder(self, folderpath):
        try:
            for root, dirs, files in os.walk(folderpath):
                for file in files:
                    filepath = os.path.join(root, file)
                    self.decrypt_file(filepath)
            QMessageBox.information(self, "成功", f"文件夹已解密: {folderpath}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    tool = EncryptTool()
    tool.show()
    sys.exit(app.exec_())
