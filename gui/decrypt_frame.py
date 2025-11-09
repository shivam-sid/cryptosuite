# gui/decrypt_frame.py

import customtkinter
from tkinter import filedialog
from gui.base_frame import BaseFrame

# Auto-detect module (keeps decrypt frame uncluttered)
from gui.auto_detect import AutoDetect

# Core operation modules
from operations import encoders, ciphers as ciphers_mod, text_converters, asymmetric_ciphers as asym_mod, hashing_core
try:
    from operations import hex as hex_ops
except Exception:
    hex_ops = None
try:
    from operations import file_io as file_io_mod
except Exception:
    file_io_mod = None


def _get_param(step_frame):
    try:
        return step_frame.param_entry.get("1.0", "end-1c").strip()
    except Exception:
        try:
            return step_frame.param_entry.get().strip()
        except Exception:
            return ""


def call_safe(module, func_name, *args, **kwargs):
    fn = getattr(module, func_name, None)
    if fn is None:
        return False, f"⚠️ '{func_name}' not implemented yet."
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        return False, f"{func_name} error: {e}"


class DecryptFrame(BaseFrame):
    def __init__(self, master, app, status_bar, **kwargs):
        self.recipe_title = "Decryption Recipe"
        self.placeholder_text = "Click an operation to begin..."
        self.load_button_text = "📂 Load"
        self.load_button_width = 70
        super().__init__(master, app, status_bar, **kwargs)

    def create_operations_sidebar(self):
        sidebar_frame = customtkinter.CTkFrame(self)
        sidebar_frame.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        sidebar_frame.grid_rowconfigure(1, weight=1)
        sidebar_frame.grid_columnconfigure(0, weight=1)

        customtkinter.CTkLabel(
            sidebar_frame, text="Operations",
            font=customtkinter.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(10, 10))

        scroll = customtkinter.CTkScrollableFrame(sidebar_frame, fg_color="transparent")
        scroll.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        scroll.grid_columnconfigure(0, weight=1)

        def sep(row):
            line = customtkinter.CTkFrame(scroll, height=1, fg_color="gray25")
            line.grid(row=row, column=0, sticky="ew", padx=10, pady=10)
            return row + 1

        r = 0
        # ---------------- Decoders ----------------

        # --- Auto-Detect button (calls gui.auto_detect.AutoDetect) ---
        customtkinter.CTkButton(
            scroll,
            text="Auto-Detect",
            anchor="w",
            fg_color="#6c63ff",
            command=lambda: AutoDetect(self).run()
        ).grid(row=r, column=0, sticky="ew", padx=20, pady=(6, 10))
        r += 1

        r = sep(r)

        customtkinter.CTkLabel(scroll, text="Decoders", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        dec_ops = [
            "From Base64", "URL-safe Base64 Decode", "From Hex", "From Binary",
            "Base32 Decode", "Base58 Decode", "Base85 Decode"
        ]
        for op in dec_ops:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1



        # ---------------- Text Tools / Converters ----------------
        customtkinter.CTkLabel(scroll, text="Text Tools / Converters", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        text_ops = [
            "To Morse", "From Morse", "Uppercase", "Lowercase", "Reverse Text",
            "Remove Spaces", "Title Case", "Capitalize Each Word"
        ]
        for op in text_ops:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1
        r = sep(r)

        # ---------------- Classic Ciphers ----------------
        customtkinter.CTkLabel(scroll, text="Classic Ciphers", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        for op in ["Caesar Decrypt", "Atbash Cipher", "ROT13 Cipher", "Vigenère Cipher"]:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1
        r = sep(r)

        # ---------------- Modern Symmetric ----------------
        customtkinter.CTkLabel(scroll, text="Modern Symmetric", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        modern = [
            "AES Decrypt", "AES-GCM Decrypt", "ChaCha20-Poly1305 Decrypt",
            "AES-CTR Decrypt", "AES-CBC Decrypt (HMAC)", "File Decrypt (stream)"
        ]
        for op in modern:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1
        r = sep(r)

        # ---------------- Asymmetric ----------------
        customtkinter.CTkLabel(scroll, text="Asymmetric", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        for op in ["RSA Decrypt", "RSA Verify", "Ed25519 Verify"]:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1
        r = sep(r)

        # ---------------- Hashing / KDF ----------------
        customtkinter.CTkLabel(scroll, text="Hashing / KDF", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        hashes = [
            "MD5", "SHA-1", "SHA-256", "SHA-512",
            "HMAC-SHA256", "HMAC-SHA512", "PBKDF2 Derive", "Argon2 Derive", "scrypt Derive"
        ]
        for op in hashes:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1
        r = sep(r)

        # ---------------- Advanced / Utility Crypto ----------------
        customtkinter.CTkLabel(scroll, text="Advanced / Utility Crypto", font=customtkinter.CTkFont(weight="bold")).grid(row=r, column=0, sticky="w", padx=10); r += 1
        advanced_ops = [
            "Shamir Combine", "BIP39 To Seed",
            "File Hash (MD5)", "File Hash (SHA256)", "File Hash (SHA512)"
        ]
        for op in advanced_ops:
            customtkinter.CTkButton(scroll, text=op, anchor="w", command=lambda o=op: self.add_recipe_step(o)).grid(
                row=r, column=0, sticky="ew", padx=10, pady=2)
            r += 1

    def execute_operation(self, operation_name, input_data, step_frame):
        p = _get_param(step_frame)

        # --- Decoders ---
        if operation_name == "From Base64":
            return call_safe(encoders, "from_base64", input_data)
        if operation_name == "URL-safe Base64 Decode":
            return call_safe(encoders, "from_base64_urlsafe", input_data)
        if operation_name == "From Hex":
            if hex_ops: return call_safe(hex_ops, "from_hex", input_data)
            return False, "Hex module missing."
        if operation_name == "From Binary":
            return call_safe(text_converters, "from_binary", input_data)

        elif operation_name == "Base32 Decode":
            return call_safe(encoders, "from_base32", input_data)
        elif operation_name == "Base58 Decode":
            return call_safe(encoders, "from_base58", input_data)
        elif operation_name == "Base85 Decode":
            return call_safe(encoders, "from_base85", input_data)

        # --- Text Tools / Converters ---
        if operation_name == "To Morse":
            return call_safe(text_converters, "to_morse", input_data)
        if operation_name == "From Morse":
            return call_safe(text_converters, "from_morse", input_data)
        if operation_name == "Uppercase":
            return True, input_data.upper()
        if operation_name == "Lowercase":
            return True, input_data.lower()
        if operation_name == "Reverse Text":
            return True, input_data[::-1]
        if operation_name == "Remove Spaces":
            return True, input_data.replace(" ", "")
        if operation_name == "Title Case":
            return True, input_data.title()
        if operation_name == "Capitalize Each Word":
            return True, " ".join(word.capitalize() for word in input_data.split())

        # --- Classic ---
        if operation_name == "Caesar Decrypt":
            try:
                shift = int(p or 3)
                return call_safe(ciphers_mod, "caesar_cipher", input_data, shift, True)
            except Exception:
                return False, "Invalid shift."
        if operation_name == "Atbash Cipher":
            return call_safe(ciphers_mod, "atbash_cipher", input_data)
        if operation_name == "ROT13 Cipher":
            return call_safe(ciphers_mod, "rot13_cipher", input_data)
        if operation_name == "Vigenère Cipher":
            if not p: return False, "Vigenère key required."
            return call_safe(ciphers_mod, "vigenere_cipher", input_data, p, True)

        # --- Modern Symmetric ---
        if operation_name == "AES Decrypt":
            return call_safe(ciphers_mod, "aes_decrypt", input_data, p)
        if operation_name == "AES-GCM Decrypt":
            return call_safe(ciphers_mod, "aes_gcm_decrypt", input_data, p or "key123")
        if operation_name == "ChaCha20-Poly1305 Decrypt":
            return call_safe(ciphers_mod, "chacha20_poly1305_decrypt", input_data, p or "key123")
        if operation_name == "AES-CTR Decrypt":
            return call_safe(ciphers_mod, "aes_ctr_decrypt", input_data, p or "key123")
        if operation_name == "AES-CBC Decrypt (HMAC)":
            return call_safe(ciphers_mod, "aes_cbc_decrypt_with_hmac", input_data, p or "key123")
        if operation_name == "File Decrypt (stream)":
            key = p or "key123"
            in_path = filedialog.askopenfilename(title="Select file to decrypt")
            if not in_path: return False, "No file selected."
            out_path = filedialog.asksaveasfilename(title="Save decrypted file as")
            if not out_path: return False, "No save path."
            mod = file_io_mod if file_io_mod else ciphers_mod
            return call_safe(mod, "file_decrypt_stream", in_path, out_path, key)

        # --- Asymmetric ---
        if operation_name == "RSA Decrypt":
            if not p: return False, "RSA private key required."
            return call_safe(asym_mod, "rsa_decrypt", input_data, p)
        if operation_name == "RSA Verify":
            return call_safe(asym_mod, "rsa_verify", input_data, p)
        if operation_name == "Ed25519 Verify":
            return call_safe(asym_mod, "ed25519_verify", input_data, p)

        # --- Hash / KDF ---
        if operation_name in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
            func = f"hash_{operation_name.lower().replace('-', '')}"
            return call_safe(hashing_core, func, input_data)
        if operation_name == "HMAC-SHA256":
            return call_safe(hashing_core, "hmac_sha256", input_data, p or "key")
        if operation_name == "HMAC-SHA512":
            return call_safe(hashing_core, "hmac_sha512", input_data, p or "key")
        if operation_name in ("PBKDF2 Derive", "Argon2 Derive", "scrypt Derive"):
            return False, f"⚙️ {operation_name} not implemented yet."

        # --- Advanced / Utility ---
        if operation_name.startswith("File Hash"):
            return False, "⚙️ File Hash placeholder."
        if operation_name in ("Shamir Combine", "BIP39 To Seed"):
            return False, f"⚙️ {operation_name} not implemented yet."

        return False, f"Unknown operation: {operation_name}"
