import sys
import os
import base64
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QFileDialog, QLineEdit, QMessageBox
from PyQt5.QtGui import QIcon
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.output_folder = os.getcwd()
        self.backup_folder = os.path.join(self.output_folder, "backup")
        os.makedirs(self.backup_folder, exist_ok=True)

    def initUI(self):
        
        self.setWindowTitle('File Encryption & Decryption')
        self.setWindowIcon(QIcon('shortcut/key.ico')) 
        self.resize(400, 250)
        
        layout = QVBoxLayout()

        self.select_file_btn = QPushButton('Select File', self)
        self.select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_btn)

        self.file_label = QLabel('No file selected', self)
        layout.addWidget(self.file_label)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Enter encryption password')
        layout.addWidget(self.password_input)

        self.encrypt_btn = QPushButton('Encrypt File', self)
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton('Decrypt File', self)
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_btn)
        
        self.use_backup_btn = QPushButton('Use Backup Key', self)
        self.use_backup_btn.clicked.connect(self.use_backup_key)
        layout.addWidget(self.use_backup_btn)

        self.change_output_btn = QPushButton('Change Output Folder', self)
        self.change_output_btn.clicked.connect(self.change_output_folder)
        layout.addWidget(self.change_output_btn)

        self.setLayout(layout)
        # self.setWindowTitle('File Encryption & Decryption')
        # self.setWindowIcon(QIcon('shortcut/keykey.ico')) 
        # self.resize(400, 250)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "Documents (*.pdf *.docx *.xlsx *.enc)", options=options)
        if file_path:
            self.file_label.setText(file_path)

    def derive_key(self, password, salt=b'static_salt'):
        return PBKDF2(password, salt, dkLen=32, count=1000000)

    def encrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text().encode()

        if not os.path.exists(file_path) or not password:
            QMessageBox.warning(self, "Error", "Please select a file and enter a password")
            return

        key = self.derive_key(password)
        cipher = AES.new(key, AES.MODE_EAX)
        
        with open(file_path, 'rb') as file:
            file_data = file.read()
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        
        encrypted_file_path = os.path.join(self.output_folder, os.path.basename(file_path) + ".enc")
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(cipher.nonce + tag + ciphertext)
        
        backup_key_path = os.path.join(self.backup_folder, os.path.basename(file_path) + "_key.txt")
        with open(backup_key_path, 'w') as backup_file:
            backup_file.write(base64.b64encode(password).decode())
        
        QMessageBox.information(self, "Success", f"File has been encrypted and saved at: {encrypted_file_path}\nKey has been saved at: {backup_key_path}")

    def decrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text().encode()

        if not os.path.exists(file_path) or not password:
            QMessageBox.warning(self, "Error", "Please select an encrypted file and enter a password")
            return

        try:
            with open(file_path, 'rb') as encrypted_file:
                nonce, tag, ciphertext = encrypted_file.read(16), encrypted_file.read(16), encrypted_file.read()
            
            key = self.derive_key(password)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            
            decrypted_file_path = os.path.join(self.output_folder, os.path.basename(file_path).replace(".enc", ""))
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            QMessageBox.information(self, "Success", f"File has been decrypted and saved at: {decrypted_file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", "Cannot decrypt file. Check password or file.")

    def use_backup_key(self):
        file_path = self.file_label.text()
        backup_key_path = os.path.join(self.backup_folder, os.path.basename(file_path).replace(".enc", "") + "_key.txt")
        
        if not os.path.exists(backup_key_path):
            QMessageBox.warning(self, "Error", "Backup key not found")
            return
        
        with open(backup_key_path, 'r') as backup_file:
            backup_key = base64.b64decode(backup_file.read()).decode()
            self.password_input.setText(backup_key)
            QMessageBox.information(self, "Success", "Backup key has been used. Try decrypting again.")

    def change_output_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder_path:
            self.output_folder = folder_path
            self.backup_folder = os.path.join(self.output_folder, "backup")
            os.makedirs(self.backup_folder, exist_ok=True)
            QMessageBox.information(self, "Success", f"Storage folder changed to: {self.output_folder}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())
