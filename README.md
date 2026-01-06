# CipherVault

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

**CipherVault** is a professional, secure file encryption tool.

## Key Features

- **Smart Dashboard**: Automatically detects if you want to Encrypt or Decrypt.
- **Secure**: Uses industry-standard AES-256 encryption.
- **Simple**: Just select a file and click Start.
- **Renamable Output**: Easily choose where to save your encrypted/decrypted files.

## Supported File Types
CipherVault works with **any file type**. It encrypts the raw binary data, so you can secure:
- **Documents**: PDF, DOCX, TXT, XLSX
- **Images**: PNG, JPG, GIF, SVG
- **Media**: MP4, MP3, MOV, WAV
- **Archives**: ZIP, RAR, 7Z, TAR
- **Executables**: EXE, MSI, BAT

## High Security Warning
> [!WARNING]
> If you lose your password or key file, your data is gone forever. There is no backdoor.

## How to use

### 1. Run the Application
Simply double-click `CipherVault.exe`. No installation required.

### 2. Encrypt a File
1.  Click **Browse Files** and select any file (image, text, pdf, etc.).
2.  The app will switch to **Green (Secure Mode)**.
3.  Enter a password or check "Use Key File" for advanced security (using key file is recommended).
4.  (Optional) Click **Change Output** to rename the destination file.
5.  Click **LOCK NOW**.

### 3. Decrypt a File
1.  Click **Browse Files** and select an encrypted file (e.g., `.enc`).
2.  The app will switch to **Red (Unlock Mode)**.
3.  Enter the password you used to encrypt it (or select the Key File).
4.  Click **UNLOCK NOW**.

## Advanced Usage (Developers)
If you want to run from source code (Windows, Mac, or Linux):
```bash
python scripts/launcher.py
```
This script will automatically check and install any missing dependencies.

### Building for Mac
If you are on macOS and want to build a standalone app:
1.  Install Python 3.
2.  Run `python scripts/build_exe.py`.
3.  Look in `dist/` for `CipherVault.app` or the executable.
