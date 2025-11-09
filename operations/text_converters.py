# operations/text_converters.py

# Morse code reference
_MORSE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ' ': '/'
}

_REVERSE_MORSE = {v: k for k, v in _MORSE_DICT.items()}

def to_morse(text: str):
    try:
        text = text.upper()
        return True, " ".join(_MORSE_DICT.get(ch, '') for ch in text)
    except Exception as e:
        return False, f"Morse encode error: {e}"

def from_morse(code: str):
    try:
        return True, "".join(_REVERSE_MORSE.get(ch, '') for ch in code.split())
    except Exception as e:
        return False, f"Morse decode error: {e}"


# --- Binary Converter ---
def to_binary(text: str):
    try:
        return True, ' '.join(format(ord(ch), '08b') for ch in text)
    except Exception as e:
        return False, f"Binary encode error: {e}"

def from_binary(data: str):
    try:
        return True, ''.join(chr(int(b, 2)) for b in data.split())
    except Exception as e:
        return False, f"Binary decode error: {e}"
