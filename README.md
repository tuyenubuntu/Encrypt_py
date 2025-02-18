# File Encryption & Decryption Application

## Introduction

This is a Python-based GUI application for encrypting and decrypting files using AES encryption. The application provides features such as file selection, encryption with password protection, decryption, backup key usage, and the ability to change the output storage folder.

## Features

- Select files for encryption/decryption
- Encrypt files using AES encryption
- Store backup encryption keys
- Decrypt files using a password or stored backup key
- Change output folder for encrypted and decrypted files
- User-friendly PyQt5 interface
- Custom application icon

## Requirements

Make sure you have the following dependencies installed:

```bash
pip install pyqt5 pycryptodome
```

## How to Run

To run the application, use the following command:

```bash
python app.py
```

## How to Build an Executable (Windows)

To create an executable file (.exe) without a console window and with a custom icon, use **PyInstaller**:

### Install PyInstaller

```bash
pip install pyinstaller
```

### Build the Executable

```bash
pyinstaller --onefile --noconsole --icon=shortcut/key.ico py.py
```

- `--onefile`: Creates a single executable file
- `--noconsole`: Hides the command prompt window
- `--icon=shortcut/key.ico`: Adds a custom icon to the executable

The `.exe` file will be located in the `dist` folder.

## Usage

1. Run the application.
2. Click **Select File** to choose a file.
3. Enter an encryption password.
4. Click **Encrypt File** to encrypt and save it.
5. To decrypt, select an encrypted file, enter the password, and click **Decrypt File**.
6. Use **Use Backup Key** if you forget the password.
7. Click **Change Output Folder** to change the default storage location.

## License

This project is open-source and available for modification and distribution.

## Author

Developed by tuyenubuntu.


