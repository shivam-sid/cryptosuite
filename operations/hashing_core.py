# operations/hashing_core.py

import hashlib, hmac, os
from base64 import b64encode

# --- Basic Hashes ---
def hash_md5(text): return True, hashlib.md5(text.encode()).hexdigest()
def hash_sha1(text): return True, hashlib.sha1(text.encode()).hexdigest()
def hash_sha256(text): return True, hashlib.sha256(text.encode()).hexdigest()
def hash_sha512(text): return True, hashlib.sha512(text.encode()).hexdigest()

# --- HMAC ---
def hmac_sha256(message: str, key: str):
    return True, hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def hmac_sha512(message: str, key: str):
    return True, hmac.new(key.encode(), message.encode(), hashlib.sha512).hexdigest()

# --- PBKDF2 ---
def pbkdf2_derive(password: str, salt: str = None, iterations: int = 100000, dklen: int = 32):
    try:
        salt = salt.encode() if salt else os.urandom(16)
        derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen)
        return True, b64encode(derived).decode()
    except Exception as e:
        return False, f"PBKDF2 derive error: {e}"

# --- Argon2 & scrypt placeholders (require extra lib) ---
def argon2_derive(password, salt="salt"):
    try:
        return True, hashlib.sha512((password + salt).encode()).hexdigest()
    except Exception as e:
        return False, f"Argon2 placeholder error: {e}"

def scrypt_derive(password, salt="salt"):
    try:
        derived = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32)
        return True, b64encode(derived).decode()
    except Exception as e:
        return False, f"scrypt derive error: {e}"
