# operations/ciphers.py
# ✅ Full version with all classical and modern symmetric ciphers implemented.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os, base64

# ---------------------------------------------------------------------------------------
# Classic Ciphers
# ---------------------------------------------------------------------------------------

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> tuple[bool, str]:
    if not isinstance(shift, int):
        return False, "Shift must be integer."
    if decrypt: shift = -shift
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
        else:
            result += char
    return True, result


def atbash_cipher(text: str) -> tuple[bool, str]:
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr(ord('z') - ord(char) + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr(ord('Z') - ord(char) + ord('A'))
        else:
            result += char
    return True, result


def rot13_cipher(text: str) -> tuple[bool, str]:
    return caesar_cipher(text, 13)


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> tuple[bool, str]:
    if not key.isalpha():
        return False, "Key must contain only letters."
    key = key.upper()
    result, key_index = "", 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            if decrypt:
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return True, result

# ---------------------------------------------------------------------------------------
# Symmetric Block Ciphers (AES, DES, 3DES, Blowfish)
# ---------------------------------------------------------------------------------------

def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def _unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

# AES (CBC Mode)
def aes_encrypt(text: str, key: str):
    try:
        key_bytes = key.encode()
        if len(key_bytes) not in (16, 24, 32):
            return False, "AES key must be 16, 24, or 32 bytes."
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(_pad(text.encode())) + enc.finalize()
        return True, base64.b64encode(iv + ct).decode()
    except Exception as e:
        return False, f"AES encrypt error: {e}"

def aes_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()
        blob = base64.b64decode(data)
        iv, ct = blob[:16], blob[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return True, _unpad(dec.update(ct) + dec.finalize()).decode()
    except Exception as e:
        return False, f"AES decrypt error: {e}"

# DES
def des_encrypt(text: str, key: str):
    try:
        key_bytes = key.encode()[:8].ljust(8, b'0')
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(_pad(text.encode())) + enc.finalize()
        return True, base64.b64encode(iv + ct).decode()
    except Exception as e:
        return False, f"DES encrypt error: {e}"

def des_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:8].ljust(8, b'0')
        blob = base64.b64decode(data)
        iv, ct = blob[:8], blob[8:]
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return True, _unpad(dec.update(ct) + dec.finalize()).decode()
    except Exception as e:
        return False, f"DES decrypt error: {e}"

# Triple DES
def triple_des_encrypt(text: str, key: str):
    try:
        key_bytes = key.encode()[:24].ljust(24, b'0')
        iv = os.urandom(8)
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(_pad(text.encode())) + enc.finalize()
        return True, base64.b64encode(iv + ct).decode()
    except Exception as e:
        return False, f"3DES encrypt error: {e}"

def triple_des_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:24].ljust(24, b'0')
        blob = base64.b64decode(data)
        iv, ct = blob[:8], blob[8:]
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return True, _unpad(dec.update(ct) + dec.finalize()).decode()
    except Exception as e:
        return False, f"3DES decrypt error: {e}"

# Blowfish
def blowfish_encrypt(text: str, key: str):
    try:
        key_bytes = key.encode()[:56].ljust(16, b'0')
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(_pad(text.encode())) + enc.finalize()
        return True, base64.b64encode(iv + ct).decode()
    except Exception as e:
        return False, f"Blowfish encrypt error: {e}"

def blowfish_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:56].ljust(16, b'0')
        blob = base64.b64decode(data)
        iv, ct = blob[:8], blob[8:]
        cipher = Cipher(algorithms.Blowfish(key_bytes), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return True, _unpad(dec.update(ct) + dec.finalize()).decode()
    except Exception as e:
        return False, f"Blowfish decrypt error: {e}"

# ---------------------------------------------------------------------------------------
# Modern Algorithms: AES-GCM / AES-CTR / AES-CBC-HMAC / ChaCha20-Poly1305
# ---------------------------------------------------------------------------------------

def aes_gcm_encrypt(plaintext: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return True, base64.b64encode(nonce + ct).decode()
    except Exception as e:
        return False, f"AES-GCM encrypt error: {e}"

def aes_gcm_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        aesgcm = AESGCM(key_bytes)
        blob = base64.b64decode(data)
        nonce, ct = blob[:12], blob[12:]
        return True, aesgcm.decrypt(nonce, ct, None).decode()
    except Exception as e:
        return False, f"AES-GCM decrypt error: {e}"

def aes_ctr_encrypt(text: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(text.encode()) + enc.finalize()
        return True, base64.b64encode(nonce + ct).decode()
    except Exception as e:
        return False, f"AES-CTR encrypt error: {e}"

def aes_ctr_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        blob = base64.b64decode(data)
        nonce, ct = blob[:16], blob[16:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        dec = cipher.decryptor()
        return True, dec.update(ct) + dec.finalize().decode()
    except Exception as e:
        return False, f"AES-CTR decrypt error: {e}"

def aes_cbc_encrypt_with_hmac(plaintext: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(_pad(plaintext.encode())) + enc.finalize()

        h = hmac.HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
        h.update(iv + ct)
        tag = h.finalize()
        return True, base64.b64encode(iv + ct + tag).decode()
    except Exception as e:
        return False, f"AES-CBC-HMAC encrypt error: {e}"

def aes_cbc_decrypt_with_hmac(data: str, key: str):
    try:
        blob = base64.b64decode(data)
        key_bytes = key.encode()[:32].ljust(32, b'0')
        iv, ct, tag = blob[:16], blob[16:-32], blob[-32:]
        h = hmac.HMAC(key_bytes, hashes.SHA256(), backend=default_backend())
        h.update(iv + ct)
        h.verify(tag)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        return True, _unpad(dec.update(ct) + dec.finalize()).decode()
    except Exception as e:
        return False, f"AES-CBC-HMAC decrypt error: {e}"

def chacha20_poly1305_encrypt(plaintext: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key_bytes)
        ct = chacha.encrypt(nonce, plaintext.encode(), None)
        return True, base64.b64encode(nonce + ct).decode()
    except Exception as e:
        return False, f"ChaCha20 encrypt error: {e}"

def chacha20_poly1305_decrypt(data: str, key: str):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        blob = base64.b64decode(data)
        nonce, ct = blob[:12], blob[12:]
        chacha = ChaCha20Poly1305(key_bytes)
        pt = chacha.decrypt(nonce, ct, None)
        return True, pt.decode()
    except Exception as e:
        return False, f"ChaCha20 decrypt error: {e}"
