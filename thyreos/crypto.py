"""
RSA Encryption/Decryption Engine for Thyreos.

This module provides RSA-2048 encryption and decryption with OAEP padding
using PyCryptodome. It supports block-based processing for large files.
"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


def generate_rsa_key(key_size=2048):
    """
    Generate an RSA key pair.

    Args:
        key_size (int): RSA key size in bits (default: 2048)

    Returns:
        tuple: (private_key_bytes, public_key_bytes)
    """
    rsa_key = RSA.generate(key_size)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    return private_key, public_key


def save_key_to_file(key, file_name):
    """
    Save a key to a file in binary format.

    Args:
        key (bytes): The key data to save
        file_name (str): Path to the output file
    """
    with open(file_name, 'wb') as f:
        f.write(key)


def load_key_from_file(file_name):
    """
    Load a key from a binary file.

    Args:
        file_name (str): Path to the key file

    Returns:
        bytes: The key data
    """
    with open(file_name, 'rb') as f:
        return f.read()


def encrypt_file(file_path, public_key):
    """
    Encrypt a file using RSA-OAEP with block processing.

    Args:
        file_path (str): Path to the file to encrypt
        public_key (bytes): RSA public key in PEM format

    Returns:
        str: Path to the encrypted file (overwrites original)
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    encrypted_data = b""
    block_size = rsa_key.size_in_bytes() - 42  # OAEP padding overhead

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_data += cipher.encrypt(block)

    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

    return file_path


def decrypt_file(file_path, private_key):
    """
    Decrypt a file using RSA-OAEP with block processing.

    Args:
        file_path (str): Path to the encrypted file
        private_key (bytes): RSA private key in PEM format

    Returns:
        str: Path to the decrypted file (overwrites encrypted)
    """
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    decrypted_data = b""
    block_size = rsa_key.size_in_bytes()

    for i in range(0, len(encrypted_data), block_size):
        block = encrypted_data[i:i + block_size]
        decrypted_data += cipher.decrypt(block)

    with open(file_path, 'wb') as f:
        f.write(decrypted_data)

    return file_path
