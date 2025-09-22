CipherVault: Secure File Encryption/Decryption program

CipherVault is a Python-based program designed for encrypting and decrypting text files using a simple byte-shifting cipher. It serves as an educational example to demonstrate fundamental encryption principles, file handling, and robust programming practices.

Features

File Encryption: Encrypts the content of a given text file.
File Decryption: Decrypts previously encrypted files using a provided key or a key stored within the encrypted file.
Key Generation: Automatically generates a random key for each encryption.
Structured Storage: Encrypted data and keys are stored in a structured JSON format (.json) for easy parsing and management.
Robust Error Handling: Includes comprehensive error handling for file operations, invalid input, and malformed encrypted files.
User-Friendly Interface: Provides a simple command-line interface for easy interaction.

How to Use

Prerequisites: Ensure you have Python 3.x installed on your system.

Run the script.

Follow the prompts. The utility will present you with options to encrypt or decrypt a file.

Encrypting a file:
Choose E for encrypt.
Enter the path to your input text file (for example, my_secret_data.txt).
Optionally, provide an output filename (default is encrypted.json).
The program will display the generated encryption key. Save this key securely, as it is required for decryption if the encrypted file is moved or corrupted.

Decrypting a file:
Choose D for decrypt.
Enter the path to your encrypted JSON file (for example, encrypted.json).
Optionally, provide an output filename for the decrypted data (default is decrypted.txt).
You will be prompted to enter the decryption key. You can either type the comma-separated key you saved earlier or press Enter to use the key stored within the encrypted.json file itself.
