import sys
import os
import base64
import psutil
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
        self.decrypted_files = []
        self.is_encrypted = False
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

        self.exit_btn = QPushButton('Exit', self)  # Thêm nút Exit
        self.exit_btn.clicked.connect(self.exit_app)
        layout.addWidget(self.exit_btn)

        self.setLayout(layout)
        
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "Documents (*.pdf *.docx *.xlsx *.enc)")
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
        
        QMessageBox.information(self, "Success", f"File encrypted: {encrypted_file_path}\nKey saved: {backup_key_path}")


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

            self.decrypted_files.append(decrypted_file_path)
            self.is_encrypted = True  # Đặt trạng thái là đã giải mã
            QMessageBox.information(self, "Success", f"File decrypted: {decrypted_file_path}")
            os.startfile(decrypted_file_path)
        except Exception:
            QMessageBox.warning(self, "Error", "Cannot decrypt file. Check password or file.")

    def use_backup_key(self):
        file_path = self.file_label.text()
        backup_key_path = os.path.join(self.backup_folder, os.path.basename(file_path).replace(".enc", "") + "_key.txt")
        
        if not os.path.exists(backup_key_path):
            QMessageBox.warning(self, "Error", "Backup key not found")
            return
        
        with open(backup_key_path, 'r') as backup_file:
            self.password_input.setText(base64.b64decode(backup_file.read()).decode())
            QMessageBox.information(self, "Success", "Backup key loaded.")
    def change_output_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder_path:
            self.output_folder = folder_path
            self.backup_folder = os.path.join(self.output_folder, "backup")
            os.makedirs(self.backup_folder, exist_ok=True)
            QMessageBox.information(self, "Success", f"Storage folder changed to: {self.output_folder}")
    def exit_app(self):
        reply = QMessageBox.question(self, "Exit", "Do you want to delete the decrypted file?", 
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            error_occurred = False
            for file_path in self.decrypted_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        QMessageBox.information(self, "Deleted", f"File deleted: {file_path}")
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Failed to delete {file_path}: {e}")
                        error_occurred = True

            if error_occurred:
                QMessageBox.warning(self, "Error", "Some files could not be deleted. Please try again later.")
            else:
                self.is_encrypted = False  # Allow closing window after deletion
                self.close()

        else:
            QMessageBox.warning(self, "Error", "You must delete the decrypted file to exit.")


    def closeEvent(self, event):
        if self.is_encrypted:  # Nếu đã mã hóa
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Notice")
            msg.setText("You can only exit using the 'Exit' button below.")
            msg.setStandardButtons(QMessageBox.Ok)
            msg.buttonClicked.connect(self.close_message_box)  # Kết nối nút OK
            msg.exec_()
            event.ignore()  # Ngăn không cho đóng cửa sổ
        else:
            event.accept()  # Cho phép đóng cửa sổ nếu chưa mã hóa

    def close_message_box(self, button):
        if button.text() == "OK":
            pass  # Khi người dùng nhấn OK, chỉ cần tắt thông báo

def is_file_open(file_path):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            if any(file_path in f.path for f in proc.open_files()):
                return proc.pid
        except Exception:
            continue
    return None

def close_file(file_path):
    pid = is_file_open(file_path)
    if pid:
        try:
            proc = psutil.Process(pid)
            proc.kill()
        except Exception:
            print(f"Failed to close process {pid}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())
