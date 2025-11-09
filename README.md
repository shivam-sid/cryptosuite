<div align="center">

# CryptoSuite 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/python-3.8%2B-green.svg?style=for-the-badge\&logo=python\&logoColor=white)

<img src="./assets/header-dark.webp" width="75%" alt="CryptoSuite - header" >

</div>

---

**CryptoSuite** is a lightweight, educational cryptography toolbox with a sleek CustomTkinter GUI. It bundles classic ciphers, modern symmetric and authenticated ciphers, asymmetric signing/verification, encoders/decoders, hash & KDF utilities, and handy text converters — all organised for quick experimentation and learning.

This README was generated from the current codebase and reflects the functionality shipped in this repository (GUI app entrypoint: `app.py`).

---

## Quick links

* Run the app: `python app.py`
* Install dependencies: `pip install -r requirements.txt`
* Primary entrypoint: `app.py`
* GUI framework: `customtkinter` (Modern-looking Tkinter wrapper)

---

## Features

* Modern GUI for encrypting/decrypting text and files.
* Classic ciphers: Caesar, Atbash, ROT13, Vigenère.
* Symmetric ciphers: AES (CBC / CTR / GCM), AES-CBC with HMAC, AES-GCM, AES-CTR, ChaCha20-Poly1305, DES / 3DES, Blowfish.
* Authenticated encryption support (AES-GCM, ChaCha20Poly1305).
* Asymmetric signing / verification: RSA sign/verify (PEM keys), Ed25519 sign/verify.
* Encoders & decoders: Base64 (and urlsafe), Base32, Base85, Hex.
* Hashes & KDFs: MD5, SHA1, SHA256, SHA512, HMAC-SHA256/512, PBKDF2, scrypt, (Argon2 placeholder implemented as a fallback).
* Text converters: Morse, Binary, Hex converters and more.
* File I/O helpers for encrypting files (note: file encryption commonly prefixes IV to ciphertext in the current implementation).
* `auto_detect` module: helpers intended to auto-detect input types / encodings (there is a GUI panel for this in `gui/auto_detect.py`).

---

## Supported operations (at-a-glance)

### Encoders / Decoders

* Base64 / URL-safe Base64
* Base32
* Base85
* Hex

### Classic Ciphers

* Caesar cipher (shift)
* Atbash
* ROT13
* Vigenère cipher

### Symmetric & Authenticated Ciphers

* AES (CBC / CTR / GCM)
* AES-CBC with HMAC (authenticated pattern)
* ChaCha20-Poly1305
* DES / Triple DES (3DES)
* Blowfish

### Asymmetric

* RSA signing & verification (PEM keys, PSS padding used in code)
* Ed25519 signing & verification

### Hashing & KDFs

* MD5, SHA1, SHA256, SHA512
* HMAC-SHA256, HMAC-SHA512
* PBKDF2
* scrypt (stdlib implementation)
* Argon2 placeholder (currently a fallback—see notes)

### Text Converters

* Hex ⇄ Text
* Morse ⇄ Text
* Binary ⇄ Text

---

## Quick start

1. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate    # macOS / Linux
.\.venv\Scripts\activate   # Windows
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the GUI:

```bash
python app.py
```

You should see the CryptoSuite GUI. Use the left-side panels to choose operation categories (Encrypt / Decrypt / Convert / Hash / Sign) and follow the on-screen fields.

---

## Example usage notes

* File encryption routines typically write the IV as a prefix to the ciphertext (so decryption reads the first bytes as IV).
* RSA sign/verify functions expect PEM-formatted keys for private/public operations.
* Some KDF placeholders (Argon2) are implemented as simplified fallbacks — to use real Argon2, install an Argon2 library (e.g. `argon2-cffi`) and replace the placeholder function with the proper implementation.

---

## Project structure (important files)

```
CryptoSuite/
├─ app.py                 # GUI entrypoint
├─ gui/                   # GUI frames and components
│  ├─ encrypt_frame.py
│  ├─ decrypt_frame.py
│  ├─ auto_detect.py      # auto-detection helpers / panel
│  └─ base_frame.py
├─ operations/            # Core crypto operations used by the GUI
│  ├─ ciphers.py
│  ├─ encoders.py
│  ├─ hashing_core.py
│  ├─ text_converters.py
│  ├─ asymmetric_ciphers.py
│  └─ file_io.py
├─ assets/                # images used in the GUI
└─ requirements.txt
```

---

## Development notes & TODOs (suggested)

* [ ] **Implement Argon2 properly** — the current `argon2_derive` in `hashing_core.py` is a placeholder that uses SHA-512. To be secure, integrate `argon2-cffi` or similar.
* [ ] **Add unit tests** for each operation in `operations/` (pytest recommended).
* [ ] **Add more robust key management** for RSA (PEM import/export helpers) and provide GUI options to load/save keys.
* [ ] **Auto-detect improvements** — wire the `auto_detect` panel to suggest operations automatically (you mentioned adding an “Auto Detect” button — the codebase already includes an `auto_detect.py` module; you can place a button in the recipe panel to call its detection functions).
* [ ] **Input validation & strong key checks** — warn when weak keys (e.g., short AES keys, DES keys) are used.
* [ ] **Packaging** — wrap into an executable with PyInstaller for non-dev users.

---

## Security & disclaimers

This project is intended for learning, experimentation and educational purposes only. Crypto implementations are notoriously tricky — **do not** use this tool for protecting sensitive production data without a proper security review and thorough testing.

---

## Contributing

Contributions welcome! Open an issue describing the feature or bug, or submit a PR. Please keep changes focused and add unit tests where possible.

---

## License

Released under the **MIT License**. See `LICENSE` (or add one if missing) for details.

---

## Acknowledgements

Inspired by community cryptography resources and educational projects. If CryptoSuite helped you, please ⭐ the repo.

---

*Generated automatically from the repository contents.*
