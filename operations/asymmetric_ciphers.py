# operations/asymmetric_ciphers.py (add below existing RSA functions)

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64

def rsa_sign(message, private_key_pem):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        signature = private_key.sign(message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True, base64.b64encode(signature).decode()
    except Exception as e:
        return False, f"RSA sign error: {e}"

def rsa_verify(message, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        msg, sig = message.split("||", 1)
        signature = base64.b64decode(sig)
        public_key.verify(signature, msg.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True, "Signature valid ✅"
    except InvalidSignature:
        return False, "Invalid signature ❌"
    except Exception as e:
        return False, f"RSA verify error: {e}"

def ed25519_sign(message, private_key_hex):
    try:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        sig = key.sign(message.encode())
        return True, sig.hex()
    except Exception as e:
        return False, f"Ed25519 sign error: {e}"

def ed25519_verify(message, public_key_hex):
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        msg, sig = message.split("||", 1)
        pub.verify(bytes.fromhex(sig), msg.encode())
        return True, "Signature valid ✅"
    except InvalidSignature:
        return False, "Invalid signature ❌"
    except Exception as e:
        return False, f"Ed25519 verify error: {e}"
