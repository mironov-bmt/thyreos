"""
Unit tests for Thyreos v2.0 Hybrid Post-Quantum Encryption Engine.

Tests ML-KEM-1024 (Kyber) + AES-256-GCM + HKDF + Argon2id full cycles.
Uses QuantCrypt for precompiled post-quantum binaries.

Run with: python -m pytest tests/
Or directly: python -m tests.test_crypto
"""

import os
import tempfile
import unittest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from thyreos.crypto import (
    generate_kyber_keypair,
    save_key_to_file,
    load_key_from_file,
    encrypt_file,
    decrypt_file,
    ThyreosError,
    InvalidKeyError,
    InvalidFileFormatError,
    DecryptionError,
    DependencyError,
)


class TestHybridCryptoEngine(unittest.TestCase):
    """Test suite for ML-KEM-1024 + AES-256-GCM hybrid encryption."""

    def test_01_generate_kyber_keypair(self):
        """Test that ML-KEM-1024 key generation returns valid keys."""
        public_key, secret_key = generate_kyber_keypair()
        # ML-KEM-1024 encapsulation key = 1568 bytes, decapsulation key = 3168 bytes
        self.assertEqual(len(public_key), 1568)
        self.assertEqual(len(secret_key), 3168)

    def test_02_save_and_load_key(self):
        """Test saving and loading an ML-KEM decapsulation key with integrity check."""
        _, secret_key = generate_kyber_keypair()

        fd, tmp_path = tempfile.mkstemp(suffix='.bin')
        os.close(fd)

        try:
            save_key_to_file(secret_key, tmp_path)
            loaded_key = load_key_from_file(tmp_path)
            self.assertEqual(loaded_key, secret_key)
        finally:
            os.unlink(tmp_path)

    def test_03_key_integrity_check(self):
        """Test that tampered key file fails integrity check."""
        _, secret_key = generate_kyber_keypair()

        fd, tmp_path = tempfile.mkstemp(suffix='.bin')
        os.close(fd)

        try:
            save_key_to_file(secret_key, tmp_path)
            # Tamper with key file (flip last byte)
            with open(tmp_path, 'r+b') as f:
                f.seek(-1, 2)
                last_byte = f.read(1)
                f.seek(-1, 2)
                f.write(bytes([last_byte[0] ^ 0xFF]))

            with self.assertRaises(InvalidKeyError):
                load_key_from_file(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_04_encrypt_decrypt_small_file(self):
        """Test full hybrid encryption/decryption cycle with small data."""
        public_key, secret_key = generate_kyber_keypair()

        original_data = b"Hello, Thyreos v2.0! Post-quantum encryption test."

        fd, tmp_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, original_data)
        os.close(fd)

        try:
            # Encrypt
            encrypted_path = encrypt_file(tmp_path, public_key)
            self.assertTrue(os.path.exists(encrypted_path))
            self.assertTrue(encrypted_path.endswith('.thyreos'))

            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            # Encrypted data should be larger (header + mlkem_ct + nonce + ct + tag)
            self.assertGreater(len(encrypted_data), len(original_data))

            # Original file should still exist
            self.assertTrue(os.path.exists(tmp_path))

            # Decrypt
            decrypted_path = decrypt_file(encrypted_path, secret_key)
            self.assertTrue(os.path.exists(decrypted_path))

            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, original_data)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            if os.path.exists(tmp_path + '.thyreos'):
                os.unlink(tmp_path + '.thyreos')
            if os.path.exists(tmp_path + '.decrypted'):
                os.unlink(tmp_path + '.decrypted')

    def test_05_encrypt_decrypt_large_file(self):
        """Test hybrid encryption with data larger than one AES block."""
        public_key, secret_key = generate_kyber_keypair()

        # 1 MB of random data
        original_data = os.urandom(1024 * 1024)

        fd, tmp_path = tempfile.mkstemp(suffix='.bin')
        os.write(fd, original_data)
        os.close(fd)

        try:
            encrypted_path = encrypt_file(tmp_path, public_key)
            decrypted_path = decrypt_file(encrypted_path, secret_key)

            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, original_data)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            if os.path.exists(tmp_path + '.thyreos'):
                os.unlink(tmp_path + '.thyreos')
            if os.path.exists(tmp_path + '.decrypted'):
                os.unlink(tmp_path + '.decrypted')

    def test_06_invalid_file_format(self):
        """Test decryption fails with invalid/corrupted file."""
        _, secret_key = generate_kyber_keypair()

        fd, tmp_path = tempfile.mkstemp(suffix='.bad')
        os.write(fd, b"NOT_A_VALID_THYREOS_FILE")
        os.close(fd)

        try:
            with self.assertRaises(InvalidFileFormatError):
                decrypt_file(tmp_path, secret_key)
        finally:
            os.unlink(tmp_path)

    def test_07_tampered_ciphertext(self):
        """Test that tampered ciphertext fails GCM authentication."""
        public_key, secret_key = generate_kyber_keypair()

        original_data = b"Sensitive post-quantum data"

        fd, tmp_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, original_data)
        os.close(fd)

        try:
            encrypted_path = encrypt_file(tmp_path, public_key)

            # Tamper with encrypted file (flip last byte)
            with open(encrypted_path, 'r+b') as f:
                f.seek(-1, 2)
                last_byte = f.read(1)
                f.seek(-1, 2)
                f.write(bytes([last_byte[0] ^ 0xFF]))

            # Decryption should fail due to invalid GCM tag
            with self.assertRaises(DecryptionError):
                decrypt_file(encrypted_path, secret_key)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            if os.path.exists(tmp_path + '.thyreos'):
                os.unlink(tmp_path + '.thyreos')

    def test_08_wrong_key_decryption(self):
        """Test that decryption with wrong key fails gracefully."""
        public_key, secret_key = generate_kyber_keypair()
        _, wrong_secret_key = generate_kyber_keypair()

        original_data = b"Test data for wrong key"

        fd, tmp_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, original_data)
        os.close(fd)

        try:
            encrypted_path = encrypt_file(tmp_path, public_key)

            # Try decrypt with wrong key
            with self.assertRaises((InvalidKeyError, DecryptionError)):
                decrypt_file(encrypted_path, wrong_secret_key)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            if os.path.exists(tmp_path + '.thyreos'):
                os.unlink(tmp_path + '.thyreos')


if __name__ == '__main__':
    unittest.main(verbosity=2)
