# 🛡️ Thyreos v2.0

> **Post-Quantum Experimental File Encryption Tool**
> 
> Named after the ancient Greek θυρεός — the shield that stood between the warrior and the enemy.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![PQC](https://img.shields.io/badge/Post--Quantum-ML--KEM--1024%2BAES--256--GCM-green)](https://pq-crystals.org/kyber/)
[![NIST](https://img.shields.io/badge/NIST-FIPS__203-purple)](https://csrc.nist.gov/projects/post-quantum-cryptography)

## 📋 Description

**Thyreos** is an experimental file encryption utility designed for **educational and research purposes** in post-quantum cryptography. 

### 🔬 Why the Evolution from RSA to Post-Quantum?

The transition from RSA-2048 to **AES-256-GCM + ML-KEM-1024** hybrid encryption was driven by fundamental vulnerabilities and limitations of classical asymmetric cryptography:

| Issue | RSA-2048 | ML-KEM-1024 (Kyber) |
|---|---|---|
| **Quantum Threat** | ❌ Vulnerable to Shor's algorithm | ✅ Resistant to quantum attacks |
| **Performance** | ❌ Slow: ~200-733ms per handshake | ✅ Fast: ~0.69ms encapsulation |
| **Key Size** | ❌ Large keys (2048-bit) | ✅ Compact: 1568B encapsulation key |
| **Security Basis** | ❌ Integer factorization | ✅ Module-LWE (lattice-based) |
| **NIST Status** | ❌ Legacy | ✅ FIPS 203 standardized (2024) |

> *"RSA and ECC will be completely broken by sufficiently large quantum computers running Shor's algorithm."*
> — [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)

> *"ML-KEM-1024 provides security equivalent to AES-256 and is designed to resist attacks from both classical and quantum computers."*
> — [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)

> *"Performance benchmarks show ML-KEM-1024 encapsulation at ~0.69ms compared to RSA-3072 at ~200ms — a 290x speedup."*
> — [Open Quantum Safe Project Benchmarks](https://openquantumsafe.org/benchmarking/)

> *"Frontiers in Physics (2026) demonstrates that hybrid post-quantum protocols combining ML-KEM with AES-256-GCM provide both quantum resistance and high performance for authenticated encryption."*
> — [Frontiers in Physics, 2026](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2026.1568918/full)

> **⚠️ Important:** This project is strictly **experimental and educational**. It explores post-quantum file protection mechanisms and is **not intended for production use** in critical security environments without formal security auditing and hardening.

## 🔐 Cryptographic Architecture

Thyreos v2.0 implements a **hybrid post-quantum encryption scheme** following NIST SP 800-108 and FIPS 203 recommendations:

```
┌─────────────────────────────────────────────────────────────┐
│  THYREOS v2.0 HYBRID ENCRYPTION PIPELINE                   │
├─────────────────────────────────────────────────────────────┤
│  1. ML-KEM-1024 (Kyber) Key Generation                      │
│     └─> Encapsulation Key (1568 bytes) + Decapsulation Key  │
│                                                             │
│  2. Encapsulation (per-file encryption)                     │
│     └─> Shared Secret (32 bytes) + ML-KEM Ciphertext          │
│                                                             │
│  3. Key Derivation (HKDF-SHA256)                            │
│     └─> AES-256-GCM Key (32 bytes)                          │
│        [NIST SP 800-108 compliant]                           │
│                                                             │
│  4. Authenticated Encryption (AES-256-GCM)                  │
│     └─> Nonce (12 bytes) + Ciphertext + Auth Tag (16 bytes)│
│                                                             │
│  5. Output Format: [Magic][Version][ML-KEM CT][Nonce][AES]  │
│     └─> Atomic blob with versioning and integrity checks     │
└─────────────────────────────────────────────────────────────┘
```

### Why This Design?

- **ML-KEM-1024** (Kyber) provides **post-quantum security** based on the hardness of the Module-LWE problem — no known efficient quantum algorithm can break it. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- **AES-256-GCM** provides **authenticated encryption** with hardware acceleration (AES-NI) on modern CPUs, achieving throughput of ~10 GB/s. [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- **HKDF-SHA256** securely derives the AES key from the KEM shared secret following [NIST SP 800-108](https://csrc.nist.gov/pubs/sp/800/108/r1/final) recommendations for key derivation functions.
- **Argon2id** protects exported keys from brute-force attacks using memory-hard key stretching. [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
- The **single-blob ciphertext format** with magic bytes (`THYR`) and version byte ensures atomic storage, forward compatibility, and tamper detection.

## 🚀 Features

- 🔐 **Post-Quantum Security**: ML-KEM-1024 (NIST FIPS 203)
- 🛡️ **Authenticated Encryption**: AES-256-GCM with 128-bit authentication tag
- 🔑 **Key Protection**: Argon2id memory-hard key stretching for exported keys
- ⚡ **High Performance**: Sub-millisecond encapsulation/decapsulation via precompiled binaries
- 📁 **Safe File Handling**: Encrypted output saved as `.thyreos` (original file preserved)
- 🎨 **Colored CLI**: Interactive console with Windows color support and tkinter file picker
- 🔑 **Automatic Key Management**: Generate, save, and load ML-KEM key pairs with integrity checks
- 🧪 **Unit Tested**: 8 tests covering key generation, save/load, full cycles, tamper detection, format validation, and error handling
- 📦 **No Compilation Required**: Precompiled wheels for Windows, Linux, macOS via QuantCrypt

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/mironov-bmt/thyreos.git
cd thyreos

# Install dependencies (no C compiler needed!)
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose | Version | Source |
|---|---|---|---|
| `pycryptodome` | AES-256-GCM, HKDF-SHA256 | >=3.15.0 | [PyCryptodome](https://www.pycryptodome.org/) |
| `quantcrypt` | ML-KEM-1024 precompiled binaries | >=1.0.0 | [QuantCrypt](https://pypi.org/project/quantcrypt/) |
| `argon2-cffi` | Argon2id key stretching | >=23.0.0 | [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) |

**Why QuantCrypt?** Unlike `liboqs-python` which requires compiling 1738 C files from source (5–15 minutes on Windows), **QuantCrypt** provides **precompiled wheels** for Windows, Linux, and macOS via PyPI. Just `pip install` and it works — no CMake, no GCC, no waiting.

**Why Argon2id?** Argon2id is the winner of the Password Hashing Competition (PHC) and recommended by [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) for password-based key derivation. It provides memory-hard resistance against GPU/ASIC brute-force attacks. [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)

## 🛠️ Usage

### Encrypt a file
```bash
python -m thyreos
# Choose 'E' for encryption, select your file, and save the Kyber secret key securely
```

### Decrypt a file
```bash
python -m thyreos
# Choose 'D' for decryption, select the encrypted file and your Kyber secret key
```

## 📁 Project Structure

```
thyreos/
├── thyreos/
│   ├── __init__.py          # Package metadata (v2.0.0)
│   ├── __main__.py          # CLI entry point
│   ├── crypto.py            # Hybrid PQC engine (ML-KEM + AES-GCM + HKDF + Argon2)
│   └── cli.py               # Interactive console interface with shield banner
├── tests/
│   ├── __init__.py
│   └── test_crypto.py       # 8 unit tests for hybrid encryption
├── requirements.txt
├── LICENSE
└── README.md
```

## ⚠️ Security Notice

This tool is provided **as-is** for **experimental and educational purposes**:

- Always store ML-KEM decapsulation keys in a **secure, offline location** (air-gapped storage, hardware security module, or encrypted USB)
- Do not encrypt critical data without **verified, tested backups**
- The authors are **not responsible** for data loss, security breaches, or misuse
- This implementation has **not undergone formal security review** or certification
- For production use, consult a **certified cryptographer** and use FIPS 140-3 validated modules

## ⚠️ Security Limitations

This implementation is **educational and experimental**:

- **Not side-channel resistant**: Python's dynamic nature prevents constant-time cryptographic operations. Do not use for high-security environments requiring protection against physical attacks or timing analysis.
- **Not formally audited**: The code has not undergone third-party security review, penetration testing, or FIPS 140-3 certification.
- **Library maturity**: QuantCrypt 1.0.0 is a young project. For production systems, consider NIST-certified implementations (e.g., OpenSSL 3.2, AWS KMS, BoringSSL).
- **Argon2id parameters**: Default parameters are tuned for interactive use (t=3, m=64MB, p=1). For high-security environments, increase memory and iterations per [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

## 📚 Research & References

### Official Standards & Specifications
- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) — Official NIST standardization of Kyber (August 2024)
- [NIST SP 800-108: Recommendation for Key Derivation Using Pseudorandom Functions](https://csrc.nist.gov/pubs/sp/800/108/r1/final) — HKDF specification
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) — AES-GCM standard
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography) — Overview of PQC standardization

### ML-KEM (Kyber) & CRYSTALS
- [CRYSTALS-Kyber Official Specification](https://pq-crystals.org/kyber/) — Reference implementation and security analysis
- [Kyber on NIST PQC Round 3](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions) — Round 3 submission documents

### Open Quantum Safe & QuantCrypt
- [Open Quantum Safe Project](https://openquantumsafe.org/) — Production-ready PQC library (liboqs)
- [QuantCrypt on PyPI](https://pypi.org/project/quantcrypt/) — Cross-platform Python PQC with precompiled wheels
- [OQS Benchmarks](https://openquantumsafe.org/benchmarking/) — Performance comparisons of PQC algorithms

### Key Derivation & Password Hashing
- [RFC 9106: Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106) — Argon2id specification and parameter recommendations
- [Argon2 PHC Winner Specification](https://github.com/P-H-C/phc-winner-argon2) — Original Password Hashing Competition winner
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — Argon2id parameter recommendations
- [RFC 5869: HKDF](https://datatracker.ietf.org/doc/html/rfc5869) — HMAC-based Extract-and-Expand Key Derivation Function
- [Nakob's Practical Cryptography: Argon2](https://cryptobook.nakov.com/mac-and-key-derivation/argon2) — Argon2 implementation guide

### Academic Papers
- **Frontiers in Physics (2026)** — ["Design and implementation of an authenticated post-quantum session protocol using ML-KEM, ML-DSA, and AES-256-GCM"](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2026.1568918/full) — Demonstrates hybrid PQC protocol design principles used in this project
- **Shor, P.W. (1994)** — ["Algorithms for Quantum Computation: Discrete Logarithms and Factoring"](https://doi.org/10.1109/SFCS.1994.365700) — Original paper proving quantum vulnerability of RSA/ECC
- **Bernstein, D.J. & Lange, T.** — ["Post-Quantum Cryptography"](https://doi.org/10.1007/978-3-540-88702-7_5) — Survey of lattice-based cryptography and Module-LWE hardness
- **Krawczyk, H. (2010)** — ["Cryptographic Extraction and Key Derivation: The HKDF Scheme"](https://eprint.iacr.org/2010/264.pdf) — Original HKDF paper with security proofs

### Why RSA is No Longer Sufficient
- RSA-2048/3072/4096 relies on **integer factorization hardness**, which is **broken in polynomial time** by Shor's algorithm on a sufficiently large quantum computer
- Even without quantum computers, RSA key sizes grow exponentially for equivalent security levels (4096-bit RSA ≈ 128-bit security, 15360-bit ≈ 256-bit security)
- ML-KEM-1024 provides **256-bit post-quantum security** with **1568-byte encapsulation keys** — far more compact and faster than RSA equivalents

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions, bug reports, and security research are welcome! Please open an issue or submit a pull request.

For security vulnerabilities, please disclose responsibly via GitHub Issues.

---

*Named after the ancient Greek θυρεός — the shield that stood between the warrior and the enemy.*
*Evolved from RSA-2048 to post-quantum hybrid encryption in pursuit of cryptographic resilience against tomorrow's threats.*
