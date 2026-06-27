# 🛡️ Thyreos

> **Experimental file encryption tool** built for educational and research purposes in data protection.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

## 📋 Description

**Thyreos** (θυρεός) — a lightweight, console-based file encryption utility named after the large oval shield of the Hellenistic armies. It uses **RSA-2048 with OAEP padding** (via PyCryptodome) to securely encrypt and decrypt files. The tool features an interactive CLI with file-picker dialogs and colored console output for better user experience.

**⚠️ Important:** This project was created for **experimental and educational purposes** to explore file protection mechanisms. It is not intended for production use in critical security environments without additional auditing and hardening.

## 🚀 Features

- 🔐 **RSA-2048 encryption** with PKCS#1 OAEP padding
- 📁 **Block-based encryption** for files of any size
- 🎨 **Colored console interface** (Windows)
- 📂 **GUI file picker** via tkinter
- 🔑 **Automatic key generation** and export
- 🔄 **One-click decrypt** with private key file selection

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/thyreos.git
cd thyreos

# Install dependencies
pip install -r requirements.txt
```

## 🛠️ Usage

### Encrypt a file
```bash
python -m thyreos
# Choose 'E' for encryption, select your file, and save the private key securely
```

### Decrypt a file
```bash
python -m thyreos
# Choose 'D' for decryption, select the encrypted file and your private key
```

## 📁 Project Structure

```
thyreos/
├── thyreos/
│   ├── __init__.py
│   ├── crypto.py      # RSA encryption/decryption engine
│   └── cli.py         # Interactive console interface
├── tests/
│   └── __init__.py
├── requirements.txt
├── LICENSE
└── README.md
```

## ⚠️ Security Notice

This tool is provided **as-is** for experimental and educational purposes:
- Always store private keys in a secure, offline location
- Do not encrypt critical data without backup
- The authors are not responsible for data loss or security breaches

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

*Named after the ancient Greek θυρεός — the shield that stood between the warrior and the enemy.*
