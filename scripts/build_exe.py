import PyInstaller.__main__
from pathlib import Path
import customtkinter
import os

def build():
    print("Building CipherVault executable...")
    
    # Get CustomTkinter path for data inclusion
    ctk_path = os.path.dirname(customtkinter.__file__)
    
    PyInstaller.__main__.run([
        'launcher.py',
        '--name=CipherVault',
        '--onefile',
        '--windowed',
        '--add-data=cipher_vault;cipher_vault',
        f'--add-data={ctk_path};customtkinter', # Explicitly add CustomTkinter assets
        '--hidden-import=PIL',
        '--clean',
        '--noconfirm',
    ])
    
    print("\nBuild complete! Check the 'dist' folder for CipherVault.exe")

if __name__ == "__main__":
    build()
