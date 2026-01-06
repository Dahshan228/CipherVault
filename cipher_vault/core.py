import base64
import os
from typing import Tuple, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CipherVaultCore:
    """
    Core encryption and decryption logic for CipherVault using AES (Fernet).
    """

    @staticmethod
    def generate_key() -> bytes:
        """
        Generates a new secure random URL-safe base64-encoded 32-byte key.
        """
        return Fernet.generate_key()

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derives a Fernet-compatible key from a password using PBKDF2HMAC.
        
        Args:
            password: The user provided password.
            salt: Optional salt. If None, a new random 16-byte salt is generated.
            
        Returns:
            Tuple[bytes, bytes]: The derived key (base64 encoded) and the salt used.
        """
        password_bytes = password.encode('utf-8')
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key, salt

    def encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypts bytes data using the provided Fernet key.
        """
        f = Fernet(key)
        return f.encrypt(data)

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts bytes data using the provided Fernet key.
        """
        f = Fernet(key)
        return f.decrypt(encrypted_data)

    def encrypt_file(self, input_path: str, output_path: str, key: bytes):
        """
        Encrypts a file and writes it to the output path.
        """
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.encrypt_data(data, key)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_path: str, output_path: str, key: bytes):
        """
        Decrypts a file and writes it to the output path.
        """
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self.decrypt_data(encrypted_data, key)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
