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

## Installation

### Windows
**No installation is required.**
1.  Download `CipherVault.exe` from the Releases page (or use the one provided).
2.  Double-click to run. It is fully standalone and requires no dependencies.

### Mac & Linux
Currently, you must build the application from source (see below).

## How to use

### 1. Encrypt a File
1.  Run the application.
2.  Click **Browse Files** and select any file.
3.  The app will switch to **Green (Secure Mode)**.
4.  Enter a strong password.
    *   *Tip: Check "Use Key File" for maximum security (recommended).*
5.  (Optional) Click **Change Output** to rename the destination file.
6.  Click **LOCK NOW**.

### 2. Decrypt a File
1.  Click **Browse Files** and select an encrypted file (`.enc`).
2.  The app will switch to **Red (Unlock Mode)**.
3.  Enter the password you used to encrypt it (or select the Key File).
4.  Click **UNLOCK NOW**.

## Advanced Usage (Building from Source)

### Running Source Code
If you want to run the python code directly:
```bash
python scripts/launcher.py
```
This script will automatically check and install any missing dependencies.

### Building for Mac/Linux
To build a standalone app on macOS or Linux:
1.  Clone this repository.
2.  Run the build script:
    ```bash
    python scripts/build_exe.py
    ```
3.  The application bundle will be created in the `dist/` directory.
