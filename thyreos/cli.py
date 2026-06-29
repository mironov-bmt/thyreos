"""
Interactive CLI for Thyreos v2.0 - Post-Quantum File Encryption.

Named after the ancient Greek θυρεός — the shield that stood
between the warrior and the enemy.

Evolved from RSA-2048 to hybrid post-quantum encryption:
ML-KEM-1024 (Kyber) + AES-256-GCM + HKDF + Argon2id
"""

import random
import sys
import traceback
from tkinter import filedialog as fd

# Fix relative imports when running file directly
if __package__ is None or __package__ == "":
    import crypto
    generate_kyber_keypair = crypto.generate_kyber_keypair
    save_key_to_file = crypto.save_key_to_file
    load_key_from_file = crypto.load_key_from_file
    encrypt_file = crypto.encrypt_file
    decrypt_file = crypto.decrypt_file
    ThyreosError = crypto.ThyreosError
    InvalidKeyError = crypto.InvalidKeyError
    InvalidFileFormatError = crypto.InvalidFileFormatError
    DecryptionError = crypto.DecryptionError
    DependencyError = crypto.DependencyError
else:
    from .crypto import (
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


def _set_console_color_windows(color_code):
    """Set Windows console text color using ctypes."""
    try:
        from ctypes import windll
        windll.Kernel32.GetStdHandle.restype = int
        h = windll.Kernel32.GetStdHandle(0xfffffff5)
        windll.Kernel32.SetConsoleTextAttribute(h, color_code)
    except Exception:
        pass


def set_color(color_code):
    """Set console text color (best effort)."""
    if sys.platform == "win32":
        _set_console_color_windows(color_code)


def pick_file(title="Select file"):
    """Open a GUI file picker dialog."""
    return fd.askopenfilename(
        title=title,
        filetypes=(("All files", "*.*"), ("Text files", "*.txt"), ("Thyreos files", "*.thyreos")),
        defaultextension=""
    )


def print_banner():
    """Print the Thyreos v2.0 ASCII shield banner."""
    set_color(random.randint(10, 15))
    print("=" * 50)
    print("          THYREOS v2.0")
    print("     Post-Quantum File Encryption")
    print("=" * 50)
    print(
        "\n"
        "        ___________\n"
        "       /           \\\n"
        "      /   * * * *   \\\n"
        "     |   *       *   |\n"
        "     |  *  _____  *  |\n"
        "     | *  /     \  * |\n"
        "     |*  |  THY  |  *|\n"
        "     |*  |  REOS |  *|\n"
        "     |*  |       |  *|\n"
        "     | *  \_____/  * |\n"
        "     |  *         *  |\n"
        "     |   * * * * *   |\n"
        "      \             /\n"
        "       \___________/\n"
    )
    print("=" * 50)
    print("  ML-KEM-1024 + AES-256-GCM | NIST FIPS 203")
    print("=" * 50)


def run_encryption():
    """Run the file encryption workflow."""
    try:
        set_color(7)
        print("\n[+] Select the file to encrypt:")
        file_path = pick_file("Select file to encrypt")
        if not file_path:
            print("[-] No file selected.")
            return
        set_color(10)
        print("[+] Generating ML-KEM-1024 key pair...")
        public_key, secret_key = generate_kyber_keypair()
        key_name = input("Enter filename to save the decapsulation key: ").strip()
        if not key_name:
            key_name = "mlkem_secret_key.bin"
        save_key_to_file(secret_key, key_name)
        set_color(7)
        print(f"[+] Decapsulation key saved to: {key_name}")
        print("[+] Encrypting file with hybrid post-quantum scheme...")
        encrypted_path = encrypt_file(file_path, public_key)
        set_color(10)
        print(f"[+] File encrypted successfully: {encrypted_path}")
        print("[!] Original file preserved. Encrypted output: .thyreos")
        print("[!] Keep your decapsulation key safe — without it, decryption is impossible!")
        print("[!] This file uses ML-KEM-1024 + AES-256-GCM hybrid encryption.")
    except DependencyError as e:
        set_color(4)
        print(f"[-] Missing dependency: {e}")
        print("[-] Run: pip install quantcrypt pycryptodome argon2-cffi")
    except FileNotFoundError as e:
        set_color(4)
        print(f"[-] File not found: {e}")
    except InvalidFileFormatError as e:
        set_color(4)
        print(f"[-] Invalid file format: {e}")
    except ThyreosError as e:
        set_color(4)
        print(f"[-] Encryption error: {e}")
    except Exception as e:
        set_color(4)
        print(f"[-] Unexpected error: {e}")
        if __debug__:
            traceback.print_exc()


def run_decryption():
    """Run the file decryption workflow."""
    try:
        set_color(7)
        print("\n[+] Select the file to decrypt (.thyreos):")
        file_path = pick_file("Select encrypted file")
        if not file_path:
            print("[-] No file selected.")
            return
        print("[+] Select the ML-KEM decapsulation key file:")
        key_file = pick_file("Select ML-KEM decapsulation key")
        if not key_file:
            print("[-] No key file selected.")
            return
        secret_key = load_key_from_file(key_file)
        set_color(7)
        print("[+] Decrypting with post-quantum hybrid scheme...")
        decrypted_path = decrypt_file(file_path, secret_key)
        set_color(10)
        print(f"[+] File decrypted successfully: {decrypted_path}")
    except DependencyError as e:
        set_color(4)
        print(f"[-] Missing dependency: {e}")
        print("[-] Run: pip install quantcrypt pycryptodome argon2-cffi")
    except FileNotFoundError as e:
        set_color(4)
        print(f"[-] File not found: {e}")
    except InvalidKeyError as e:
        set_color(4)
        print(f"[-] Invalid key: {e}")
        print("[-] Ensure you are using the correct decapsulation key for this file.")
    except InvalidFileFormatError as e:
        set_color(4)
        print(f"[-] Invalid encrypted file: {e}")
        print("[-] The file may be corrupted or not a valid Thyreos v2.0 encrypted file.")
    except DecryptionError as e:
        set_color(4)
        print(f"[-] Decryption failed: {e}")
        print("[-] The file may have been tampered with or the key is incorrect.")
    except ThyreosError as e:
        set_color(4)
        print(f"[-] Decryption error: {e}")
    except Exception as e:
        set_color(4)
        print(f"[-] Unexpected error: {e}")
        if __debug__:
            traceback.print_exc()


def main():
    """Main entry point for the CLI."""
    print_banner()
    while True:
        set_color(10)
        print("\n[*] Thyreos v2.0 - Post-Quantum Hybrid Encryption")
        option = input(
            "\nEnter E for encryption, D for decryption, or 0 to exit: "
        ).strip().upper()
        if option in ("E", "У"):
            run_encryption()
        elif option in ("D", "В"):
            run_decryption()
        elif option == "0":
            print("\nGoodbye! Stay quantum-safe.")
            break
        else:
            set_color(4)
            print("[-] Invalid input! Please enter E, D, or 0.")


if __name__ == "__main__":
    main()