# operations/file_io.py

import hashlib, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

CHUNK_SIZE = 64 * 1024

def file_encrypt_stream(in_path, out_path, key):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()

        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(iv)
            while chunk := fin.read(CHUNK_SIZE):
                padded = padder.update(chunk)
                fout.write(encryptor.update(padded))
            fout.write(encryptor.update(padder.finalize()) + encryptor.finalize())

        return True, "File encrypted successfully."
    except Exception as e:
        return False, f"File encryption error: {e}"

def file_decrypt_stream(in_path, out_path, key):
    try:
        key_bytes = key.encode()[:32].ljust(32, b'0')
        with open(in_path, "rb") as fin:
            iv = fin.read(16)
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            with open(out_path, "wb") as fout:
                while chunk := fin.read(CHUNK_SIZE):
                    data = decryptor.update(chunk)
                    fout.write(unpadder.update(data))
                fout.write(unpadder.finalize())
        return True, "File decrypted successfully."
    except Exception as e:
        return False, f"File decryption error: {e}"

def file_hash_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return True, h.hexdigest()

def file_hash_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return True, h.hexdigest()

def file_hash_sha512(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return True, h.hexdigest()
