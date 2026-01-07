import PyInstaller.__main__
from pathlib import Path
import customtkinter
import os

def build():
    print("Building CipherVault executable...")
    
    # Get CustomTkinter path for data inclusion
    ctk_path = os.path.dirname(customtkinter.__file__)
    
    # Determine separator based on OS
    if os.name == 'nt':
        sep = ';'
    else:
        sep = ':'

    args = [
        'scripts/launcher.py',
        '--name=CipherVault',
        '--onefile',
        '--windowed',
        '--paths=.',
        f'--add-data=cipher_vault{sep}cipher_vault',
        f'--add-data={ctk_path}{sep}customtkinter',
        '--hidden-import=PIL',
        '--clean',
        '--noconfirm',
    ]

    # Mac specific optimization (optional, produces .app but --onefile is usually fine too)
    # PyInstaller usually handles basic .app creation on Mac automatically with --windowed
    
    PyInstaller.__main__.run(args)
    
    print("\nBuild complete! Check the 'dist' folder for CipherVault.exe")

if __name__ == "__main__":
    build()
