"""
generate_key(length)
Creates a random key as a list of integers.
key_range = (1, 255) for byte operations.
Start with key = [].
Loop from 0 to length - 1:
    key.append(random integer between key_range[0] and key_range[1])
Return key.

encrypt_data(data)
Convert input data to UTF-8 bytes.
Generate a key with same length as data_bytes.
encrypted_parts = []
For each byte in data_bytes and shift in key:
    encrypted_byte = (byte + shift) % 256
    encrypted_parts.append(encrypted_byte)
Return encrypted_parts and key.

decrypt_data(encrypted_data, key)
Input: encrypted_data (list of ints), key (list of ints).
Precondition: len(encrypted_data) == len(key).
decrypted_bytes = []
For each encrypted_byte and shift in key:
    decrypted_byte = (encrypted_byte - shift) % 256
    decrypted_bytes.append(decrypted_byte)
Convert decrypted_bytes to UTF-8 string.
Return decrypted string.

read_file(file_path)
Read content from a file with error handling.
Check if file exists and is not empty.
Return file content as a stripped string.

save_encrypted_file(file_path, encrypted_data, key)
Save encrypted_data and key to a JSON file.
Create dict with encrypted_data, key, version.
Write dict to file_path as JSON with indentation.

load_encrypted_file(file_path)
Load encrypted_data and key from JSON file.
Parse file as JSON.
Extract encrypted_data and key.
Handle JSONDecodeError and KeyError.
Return encrypted_data and key.

save_decrypted_file(file_path, decrypted_data)
Save decrypted_data (string) to a file.

encrypt_file(input_filename, output_filename="encrypted.json")
Read input_filename.
Encrypt data with encrypt_data.
Save encrypted data and key with save_encrypted_file.
Print success message.
Return key or None on error.

decrypt_file(input_filename, key=None, output_filename="decrypted.txt")
Load encrypted_data and file_key with load_encrypted_file.
Use provided key if available, else file_key.
Decrypt data with decrypt_data.
Save decrypted data with save_decrypted_file.
Print success message.
Return True on success, False on error.

parse_key_input(key_input)
Parse comma-separated string into list of ints.
Validate each int is within key_range.
Return parsed key or None if input empty.
Raise ValueError for invalid formats or values.

main()
Initialize CipherVault object.
Show welcome message and menu (Encrypt, Decrypt, Quit).
Loop for user choice:
  If 'E': ask for filenames, call encrypt_file, print key.
  If 'D': ask for filenames and key, parse key, call decrypt_file.
  If 'Q': quit loop.
  Else: print error message.
"""


import random
import json
from pathlib import Path
from typing import List, Tuple, Optional


class CipherVault:

    def __init__(self):
        self.key_range: Tuple[int, int] = (1, 255)

    def generate_key(self, length: int) -> List[int]:
        """Generate a random key as a list of integers within the defined key_range."""
        return [random.randint(*self.key_range) for _ in range(length)]

    def encrypt_data(self, data: str) -> Tuple[List[int], List[int]]:
        """
        Encrypt string data using a randomly generated key.

        The data is first encoded to UTF-8 bytes. Each byte is then shifted
        by a corresponding key value, with a modulo 256 operation to ensure
        the encrypted byte remains within the valid byte range (0-255).

        Args:
            data (str): The string data to be encrypted.

        Returns:
            tuple: A tuple containing two lists of integers:
                   - encrypted_data (List[int]): The list of encrypted byte values.
                   - key (List[int]): The key used for encryption.
        """
        data_bytes = data.encode('utf-8')
        key = self.generate_key(len(data_bytes))

        encrypted_data = [
            (byte + shift) % 256  # Use modulo to handle overflow and keep in byte range
            for byte, shift in zip(data_bytes, key)
        ]

        return encrypted_data, key

    def decrypt_data(self, encrypted_data: List[int], key: List[int]) -> str:
        """
        Decrypt data using the provided key.

        Each encrypted byte is shifted back by its corresponding key value,
        using a modulo 256 operation to correctly reverse the encryption.
        The resulting bytes are then decoded back into a UTF-8 string.

        Args:
            encrypted_data (List[int]): List of encrypted integer byte values.
            key (List[int]): List of key integers used for decryption.

        Returns:
            str: The decrypted string.

        Raises:
            ValueError: If encrypted_data and key do not have the same length.
        """
        if len(encrypted_data) != len(key):
            raise ValueError("Encrypted data and key must have the same length.")

        decrypted_bytes = [
            (encrypted_byte - shift) % 256  # Use modulo to handle underflow and keep in byte range
            for encrypted_byte, shift in zip(encrypted_data, key)
        ]

        return bytes(decrypted_bytes).decode('utf-8')

    def read_file(self, file_path: str) -> str:
        """Read content from a file with robust error handling."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File '{file_path}' not found.")

        if path.stat().st_size == 0:
            raise ValueError(f"File '{file_path}' is empty.")

        return path.read_text(encoding='utf-8').strip()

    def save_encrypted_file(self, file_path: str, encrypted_data: List[int], key: List[int]):
        """Save encrypted data and key to a JSON file for structured storage."""
        data = {
            "encrypted_data": encrypted_data,
            "key": key,
            "version": "1.0"  # Versioning for future compatibility
        }
        try:
            Path(file_path).write_text(json.dumps(data, indent=2), encoding='utf-8')
        except IOError as e:
            raise IOError(f"Could not write to file '{file_path}': {e}")

    def load_encrypted_file(self, file_path: str) -> Tuple[List[int], List[int]]:
        """Load encrypted data and key from a JSON file."""
        try:
            file_content = self.read_file(file_path)
            data = json.loads(file_content)
            # Validate required keys are present
            if "encrypted_data" not in data or "key" not in data:
                raise KeyError("Missing 'encrypted_data' or 'key' in file.")
            return data["encrypted_data"], data["key"]
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid encrypted file format or missing data: {e}")
        except FileNotFoundError:
            raise # Re-raise FileNotFoundError from read_file
        except ValueError:
            raise # Re-raise ValueError from read_file (empty file)

    def save_decrypted_file(self, file_path: str, decrypted_data: str):
        """Save decrypted data to a file."""
        try:
            Path(file_path).write_text(decrypted_data, encoding='utf-8')
        except IOError as e:
            raise IOError(f"Could not write to file '{file_path}': {e}")

    def encrypt_file(self, input_filename: str, output_filename: str = "encrypted.json") -> Optional[List[int]]:
        """
        Encrypt a file and save the result to a JSON file.

        Args:
            input_filename (str): Path to the file to encrypt.
            output_filename (str, optional): Path to save the encrypted data.
                                             Defaults to "encrypted.json".

        Returns:
            Optional[List[int]]: The encryption key if successful, None otherwise.
        """
        try:
            original_data = self.read_file(input_filename)
            encrypted_data, key = self.encrypt_data(original_data)
            self.save_encrypted_file(output_filename, encrypted_data, key)

            print(f"✓ File encrypted successfully and saved to '{output_filename}'")
            return key

        except (FileNotFoundError, ValueError, IOError) as e:
            print(f"Error during encryption: {e}")
            return None

    def decrypt_file(self, input_filename: str, key: Optional[List[int]] = None,
                     output_filename: str = "decrypted.txt") -> bool:
        """
        Decrypt a file using either a provided key or the key stored within the file.

        Args:
            input_filename (str): Path to the encrypted JSON file.
            key (Optional[List[int]], optional): The decryption key. If None,
                                                  the key from the file will be used.
                                                  Defaults to None.
            output_filename (str, optional): Path to save the decrypted data.
                                             Defaults to "decrypted.txt".

        Returns:
            bool: True if decryption is successful, False otherwise.
        """
        try:
            encrypted_data, file_key = self.load_encrypted_file(input_filename)

            # Use provided key or fall back to file key
            decryption_key = key if key is not None else file_key

            decrypted_data = self.decrypt_data(encrypted_data, decryption_key)
            self.save_decrypted_file(output_filename, decrypted_data)

            print(f" File decrypted successfully and saved to '{output_filename}'")
            return True

        except (FileNotFoundError, ValueError, UnicodeDecodeError, IOError) as e:
            print(f"✗ Error during decryption: {e}")
            return False

    def parse_key_input(self, key_input: str) -> Optional[List[int]]:
        """Parse comma-separated key input string into a list of integers.

        Args:
            key_input (str): A string containing comma-separated integers representing the key.

        Returns:
            Optional[List[int]]: A list of integers if the input is valid and not empty,
                                 otherwise None.

        Raises:
            ValueError: If the key format is invalid or key values are out of range.
        """
        if not key_input.strip():
            return None

        try:
            key_parts = [int(x.strip()) for x in key_input.split(',')]

            # Validate key values are in acceptable range
            for value in key_parts:
                if not (self.key_range[0] <= value <= self.key_range[1]):
                    raise ValueError(
                        f"Key values must be between {self.key_range[0]} and {self.key_range[1]} (inclusive)."
                    )

            return key_parts

        except ValueError as e:
            raise ValueError(f"Invalid key format: {e}")


def main():
    """Main program loop for the CipherVault."""
    cipher = CipherVault()

    print("\n" + "=" * 50)
    print("""Welcome to CipherVault - Secure File Encryption/Decryption
""")
    print("""This program allows you to encrypt and decrypt text files
using a simple byte-shifting cipher. Encrypted data and keys are
stored in a structured JSON format.
""")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  [E] Encrypt a file")
        print("  [D] Decrypt a file")
        print("  [Q] Quit")

        choice = input("\nSelect an option: ").strip().upper()

        if choice == 'E':
            filename = input("Enter the path to the file to encrypt: ").strip()
            output_file = input("Enter output filename (default: 'encrypted.json'): ").strip()

            if not output_file:
                output_file = "encrypted.json"

            key = cipher.encrypt_file(filename, output_file)
            if key:
                print(f"\nEncryption key: {','.join(map(str, key))}")
                print("IMPORTANT: Save this key securely! You'll need it to decrypt if the file is moved or corrupted.")

        elif choice == 'D':
            filename = input("Enter the path to the encrypted file (e.g., 'encrypted.json'): ").strip()
            output_file = input("Enter output filename for decrypted data (default: 'decrypted.txt'): ").strip()

            if not output_file:
                output_file = "decrypted.txt"

            key_input = input("Enter decryption key (comma-separated, or press Enter to use key from file): ").strip()

            try:
                key = cipher.parse_key_input(key_input) if key_input else None
                cipher.decrypt_file(filename, key, output_file)
            except ValueError as e:
                print(f"✗ Error: {e}")

        elif choice == 'Q':
            print("\nGoodbye! Thank you for using CipherVault.")
            break

        else:
            print("✗ Invalid option. Please select E, D, or Q.")
main()