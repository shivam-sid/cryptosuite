# operations/encoders.py
# ✅ Fully implemented Base Encoders/Decoders for CryptoSuite

import base64

# ---------------------------------------------------------------------------------------
# BASE64 + URL-safe Base64
# ---------------------------------------------------------------------------------------

def to_base64(text: str):
    try:
        return True, base64.b64encode(text.encode()).decode()
    except Exception as e:
        return False, f"Base64 encode error: {e}"

def from_base64(data: str):
    try:
        return True, base64.b64decode(data.encode()).decode(errors="ignore")
    except Exception as e:
        return False, f"Base64 decode error: {e}"

def to_base64_urlsafe(text: str):
    try:
        return True, base64.urlsafe_b64encode(text.encode()).decode()
    except Exception as e:
        return False, f"URL-safe Base64 encode error: {e}"

def from_base64_urlsafe(data: str):
    try:
        return True, base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")
    except Exception as e:
        return False, f"URL-safe Base64 decode error: {e}"


# ---------------------------------------------------------------------------------------
# BASE32
# ---------------------------------------------------------------------------------------

def to_base32(text: str):
    try:
        return True, base64.b32encode(text.encode()).decode()
    except Exception as e:
        return False, f"Base32 encode error: {e}"

def from_base32(data: str):
    try:
        return True, base64.b32decode(data.encode()).decode(errors="ignore")
    except Exception as e:
        return False, f"Base32 decode error: {e}"


# ---------------------------------------------------------------------------------------
# BASE58 — using Bitcoin alphabet
# ---------------------------------------------------------------------------------------

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {char: index for index, char in enumerate(_B58_ALPHABET)}

def to_base58(text: str):
    try:
        num = int.from_bytes(text.encode(), "big")
        encoded = b""
        while num > 0:
            num, rem = divmod(num, 58)
            encoded = _B58_ALPHABET[rem:rem+1] + encoded
        return True, encoded.decode()
    except Exception as e:
        return False, f"Base58 encode error: {e}"

def from_base58(data: str):
    try:
        num = 0
        for c in data.encode():
            if c not in _B58_MAP:
                return False, f"Invalid Base58 character: {chr(c)}"
            num = num * 58 + _B58_MAP[c]
        decoded = num.to_bytes((num.bit_length() + 7) // 8, "big")
        return True, decoded.decode(errors="ignore")
    except Exception as e:
        return False, f"Base58 decode error: {e}"


# ---------------------------------------------------------------------------------------
# BASE85 (Ascii85)
# ---------------------------------------------------------------------------------------

def to_base85(text: str):
    try:
        return True, base64.a85encode(text.encode()).decode()
    except Exception as e:
        return False, f"Base85 encode error: {e}"

def from_base85(data: str):
    try:
        return True, base64.a85decode(data.encode()).decode(errors="ignore")
    except Exception as e:
        return False, f"Base85 decode error: {e}"


# ---------------------------------------------------------------------------------------
# Helper for GUI-friendly error handling
# ---------------------------------------------------------------------------------------

def safe_decode_result(result):
    """
    Utility for frames that need to show a readable error message.
    Example: status, output = from_base64(user_input)
    """
    status, data = result
    return (status, data if status else f"❌ {data}")
