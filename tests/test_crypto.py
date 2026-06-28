"""
Unit tests for Thyreos RSA encryption/decryption engine.

Run from project root:
    python -m pytest tests/
Or directly:
    python -m tests.test_crypto
"""

import os
import tempfile
import unittest

from thyreos.crypto import (
    generate_rsa_key,
    save_key_to_file,
    load_key_from_file,
    encrypt_file,
    decrypt_file,
)


class TestCryptoEngine(unittest.TestCase):
    """Test suite for RSA crypto operations."""

    def test_generate_rsa_key(self):
        """Test that RSA key generation returns a valid key pair."""
        private_key, public_key = generate_rsa_key()
        self.assertTrue(private_key.startswith(b'-----BEGIN RSA PRIVATE KEY-----'))
        self.assertTrue(public_key.startswith(b'-----BEGIN PUBLIC KEY-----'))

    def test_save_and_load_key(self):
        """Test saving and loading a key from file."""
        private_key, _ = generate_rsa_key()

        fd, tmp_path = tempfile.mkstemp(suffix='.pem')
        os.close(fd)

        try:
            save_key_to_file(private_key, tmp_path)
            loaded_key = load_key_from_file(tmp_path)
            self.assertEqual(loaded_key, private_key)
        finally:
            os.unlink(tmp_path)

    def test_encrypt_decrypt_cycle(self):
        """Test full encryption and decryption cycle preserves data."""
        private_key, public_key = generate_rsa_key()

        original_data = b"Hello, Thyreos! This is a test message for RSA encryption."

        fd, tmp_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, original_data)
        os.close(fd)

        try:
            # Encrypt
            encrypt_file(tmp_path, public_key)
            with open(tmp_path, 'rb') as f:
                encrypted_data = f.read()
            self.assertNotEqual(encrypted_data, original_data)

            # Decrypt
            decrypt_file(tmp_path, private_key)
            with open(tmp_path, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, original_data)
        finally:
            os.unlink(tmp_path)

    def test_encrypt_decrypt_large_file(self):
        """Test encryption/decryption with data larger than one RSA block."""
        private_key, public_key = generate_rsa_key()

        # Data larger than 2048-bit RSA block minus OAEP padding (256 - 42 = 214 bytes)
        original_data = b"A" * 500

        fd, tmp_path = tempfile.mkstemp(suffix='.bin')
        os.write(fd, original_data)
        os.close(fd)

        try:
            encrypt_file(tmp_path, public_key)
            decrypt_file(tmp_path, private_key)

            with open(tmp_path, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, original_data)
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main()
