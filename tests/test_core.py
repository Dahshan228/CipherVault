import pytest
import os
from cipher_vault.core import CipherVaultCore

@pytest.fixture
def core():
    return CipherVaultCore()

def test_generate_key(core):
    key = core.generate_key()
    assert len(key) > 0
    assert isinstance(key, bytes)

def test_encryption_decryption(core):
    key = core.generate_key()
    data = b"Hello, World! This is a test."
    
    encrypted = core.encrypt_data(data, key)
    assert encrypted != data
    
    decrypted = core.decrypt_data(encrypted, key)
    assert decrypted == data

def test_derive_key(core):
    password = "secure_password"
    key1, salt1 = core.derive_key_from_password(password)
    key2, salt2 = core.derive_key_from_password(password, salt1)
    
    assert key1 == key2
    assert salt1 == salt2
    
def test_derive_key_different_salts(core):
    password = "secure_password"
    key1, salt1 = core.derive_key_from_password(password)
    key2, salt2 = core.derive_key_from_password(password)
    
    # Salts should be random, so keys should differ
    assert key1 != key2
    assert salt1 != salt2

def test_file_encryption(core, tmp_path):
    input_file = tmp_path / "input.txt"
    input_file.write_text("Secret Data", encoding='utf-8')
    
    output_file = tmp_path / "output.enc"
    decrypted_file = tmp_path / "decrypted.txt"
    
    key = core.generate_key()
    
    core.encrypt_file(str(input_file), str(output_file), key)
    assert output_file.exists()
    
    core.decrypt_file(str(output_file), str(decrypted_file), key)
    assert decrypted_file.exists()
    
    assert decrypted_file.read_text(encoding='utf-8') == "Secret Data"
