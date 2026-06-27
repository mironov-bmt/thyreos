"""
Interactive CLI for Thyreos file encryption tool.

Named after the ancient Greek θυρεός — the shield that stood
between the warrior and the enemy.
"""

import random
import sys
from tkinter import filedialog as fd

# Fix relative imports when running file directly
if __package__ is None or __package__ == "":
    import crypto
    generate_rsa_key = crypto.generate_rsa_key
    save_key_to_file = crypto.save_key_to_file
    load_key_from_file = crypto.load_key_from_file
    encrypt_file = crypto.encrypt_file
    decrypt_file = crypto.decrypt_file
else:
    from .crypto import (
        generate_rsa_key,
        save_key_to_file,
        load_key_from_file,
        encrypt_file,
        decrypt_file,
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
        filetypes=(("All files", "*.*"), ("Text files", "*.txt")),
        defaultextension=""
    )


def print_banner():
    """Print the Thyreos ASCII shield banner."""
    set_color(random.randint(10, 15))
    print("=" * 40)
    print("             THYREOS")
    print("=" * 40)
    print(
        "\n"
        "        ___________\n"
        "       /           \\\n"
        "      /   * * * *   \\\n"
        "     |   *       *   |\n"
        "     |  *  _____  *  |\n"
        "     | *  /     \  * |\n"
        "     |*  |       |  *|\n"
        "     |*  |  THY  |  *|\n"
        "     |*  |  REOS |  *|\n"
        "     |*  |       |  *|\n"
        "     | *  \_____/  * |\n"
        "     |  *         *  |\n"
        "     |   * * * * *   |\n"
        "      \             /\n"
        "       \___________/\n"
    )
    print("=" * 40)


def run_encryption():
    """Run the file encryption workflow."""
    try:
        set_color(7)
        print("Select the file to encrypt:")
        file_path = pick_file("Select file to encrypt")
        if not file_path:
            print("No file selected.")
            return
        private_key, public_key = generate_rsa_key()
        key_name = input("Enter filename to save the private key: ").strip()
        if not key_name:
            key_name = "private_key.pem"
        save_key_to_file(private_key, key_name)
        encrypt_file(file_path, public_key)
        set_color(10)
        print(f"[+] File encrypted successfully: {file_path}")
        print(f"[+] Private key saved to: {key_name}")
        print("[!] Keep your private key safe — without it, decryption is impossible!")
    except FileNotFoundError:
        set_color(4)
        print("[-] File not found!")
    except Exception as e:
        set_color(4)
        print(f"[-] Encryption error: {e}")


def run_decryption():
    """Run the file decryption workflow."""
    try:
        set_color(7)
        print("Select the file to decrypt:")
        file_path = pick_file("Select file to decrypt")
        if not file_path:
            print("No file selected.")
            return
        print("Select the private key file:")
        key_file = pick_file("Select private key")
        if not key_file:
            print("No key file selected.")
            return
        private_key = load_key_from_file(key_file)
        decrypt_file(file_path, private_key)
        set_color(10)
        print(f"[+] File decrypted successfully: {file_path}")
    except FileNotFoundError:
        set_color(4)
        print("[-] File or private key not found!")
    except Exception as e:
        set_color(4)
        print(f"[-] Decryption error: {e}")


def main():
    """Main entry point for the CLI."""
    print_banner()
    while True:
        set_color(10)
        option = input(
            "\nEnter E for encryption, D for decryption, or 0 to exit: "
        ).strip().upper()
        if option in ("E", "У"):
            run_encryption()
        elif option in ("D", "В"):
            run_decryption()
        elif option == "0":
            print("\nGoodbye!")
            break
        else:
            set_color(4)
            print("[-] Invalid input! Please enter E, D, or 0.")


if __name__ == "__main__":
    main()