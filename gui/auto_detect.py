# gui/auto_detect.py
# Modular Auto-Detect for CryptoSuite
# - fast heuristics only (snappy)
# - UI result window (CTkToplevel)
# - public API: AutoDetect(frame).run()

import re
import base64
import binascii
import textwrap
import customtkinter


class AutoDetect:
    def __init__(self, owner_frame):
        """
        owner_frame: instance of DecryptFrame (or any frame with:
          - _get_current_input() -> str
          - add_recipe_step(op_name)
          - app.show_toast(...)
        """
        self.frame = owner_frame
        self.app = getattr(owner_frame, "app", None)

    # ---------------------------
    # Heuristics / helpers
    # ---------------------------
    def _is_printable_ascii(self, b: bytes) -> bool:
        return all(32 <= c < 127 for c in b)

    def _looks_like_base64(self, s: str) -> bool:
        s = s.strip()
        # quick charset and decode attempt
        if re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", s):
            try:
                base64.b64decode(s, validate=True)
                return True
            except Exception:
                return False
        if re.fullmatch(r"[A-Za-z0-9_\-=\r\n]+", s):
            try:
                base64.urlsafe_b64decode(s)
                return True
            except Exception:
                return False
        return False

    def _looks_like_hex(self, s: str) -> bool:
        s = re.sub(r"\s+", "", s)
        return bool(re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0)

    def _looks_like_base58(self, s: str) -> bool:
        return bool(re.fullmatch(r"[123456789A-HJ-NP-Za-km-z]+", s) and len(s) > 3)

    def _looks_like_base85(self, s: str) -> bool:
        return len(s) > 8 and all(33 <= ord(ch) <= 117 for ch in s)

    def _detect_cipher_like(self, b: bytes) -> dict:
        # quick, not exhaustive
        l = len(b)
        suggestions = []
        if l >= 16:
            first16 = b[:16]
            if not self._is_printable_ascii(first16):
                suggestions.append(("AES (CBC/GCM likely)", 0.9))
        if l >= 8:
            first8 = b[:8]
            if not self._is_printable_ascii(first8):
                suggestions.append(("DES/3DES (possible)", 0.5))
        if l % 16 == 0 and l > 16:
            suggestions.append(("Block-aligned ciphertext (16-byte blocks)", 0.55))
        return {"suggestions": suggestions, "length": l}

    # ---------------------------
    # Core detect method (fast)
    # ---------------------------
    def detect(self, s: str) -> dict:
        s = s.strip()
        result = {"detected": [], "confidence": 0.0, "details": [], "suggestion": None}

        # Base64
        if self._looks_like_base64(s):
            result["detected"].append("Base64")
            result["confidence"] = max(result["confidence"], 0.9)
            result["details"].append("Top-layer looks like Base64 (valid characters and decode attempt passed).")
            try:
                decoded = base64.b64decode(s)
                if not self._is_printable_ascii(decoded[:64]):
                    result["details"].append("Decoded Base64 contains non-printable bytes — likely an encrypted blob inside Base64.")
                    result["suggestion"] = ("Base64 Decode → then try AES/3DES/ChaCha20", 0.85)
                else:
                    result["suggestion"] = ("Base64 Decode", 0.98)
            except Exception:
                result["details"].append("Base64 decode attempt failed (but charset matched).")

        # Hex
        if self._looks_like_hex(s):
            result["detected"].append("Hex")
            result["confidence"] = max(result["confidence"], 0.85)
            result["details"].append("Input is valid hexadecimal (even length).")
            try:
                raw = binascii.unhexlify(re.sub(r"\s+", "", s))
                cipher_like = self._detect_cipher_like(raw)
                if cipher_like["suggestions"]:
                    result["details"].append("Hex-decoded bytes look like encrypted data (IV-like prefix or non-printable).")
                    result["suggestion"] = ("Hex Decode → then try AES/3DES", 0.9)
            except Exception:
                result["details"].append("Hex decode failed (unexpected).")

        # Base58 / Base85
        if self._looks_like_base58(s):
            result["detected"].append("Base58")
            result["details"].append("Matches Base58 alphabet and length heuristics.")
            result["confidence"] = max(result["confidence"], 0.6)
            result["suggestion"] = ("Base58 Decode", 0.6)
        if self._looks_like_base85(s):
            result["detected"].append("Base85/Ascii85")
            result["details"].append("Looks like Base85/Ascii85 text.")
            result["confidence"] = max(result["confidence"], 0.6)
            result["suggestion"] = ("Base85 Decode", 0.6)

        # Hash-like quick checks
        if re.fullmatch(r"[0-9a-fA-F]{32}", s):
            result["detected"].append("Possible MD5 hash")
            result["details"].append("Exact 32 hex characters (MD5-length).")
            result["confidence"] = max(result["confidence"], 0.8)
        if re.fullmatch(r"[0-9a-fA-F]{40}", s):
            result["detected"].append("Possible SHA-1 hash")
            result["confidence"] = max(result["confidence"], 0.8)

        # Binary sniff fallback
        if not result["detected"]:
            try:
                b = base64.b64decode(s, validate=False)
                nonprint = sum(1 for c in b[:64] if c < 32 or c > 126)
                if nonprint > 4:
                    result["detected"].append("Binary / Encrypted blob")
                    result["details"].append("Top-layer looks like binary data (not printable text).")
                    result["confidence"] = 0.6
                    result["suggestion"] = ("Try AES/3DES/ChaCha20 decryption (choose manually)", 0.6)
            except Exception:
                # leave unknown
                pass

        if not result["detected"]:
            result["details"].append("No clear encoding or cipher detected.")
            result["confidence"] = 0.0
            result["suggestion"] = ("Manual selection required", 0.0)

        return result

    # ---------------------------
    # Small UI: result window and actions
    # ---------------------------
    def _show_result_window(self, input_text: str, result: dict):
        header = "Auto-Detect Results"
        detected = result.get("detected", [])
        confidence = result.get("confidence", 0.0)
        details = result.get("details", [])
        suggestion = result.get("suggestion", None)

        # Build the top-level window
        win = customtkinter.CTkToplevel(self.frame)
        win.title("Auto-Detect")
        win.geometry("520x320")
        win.attributes("-topmost", True)

        header_frame = customtkinter.CTkFrame(win, corner_radius=6)
        header_frame.pack(fill="x", padx=12, pady=(12, 6))
        customtkinter.CTkLabel(header_frame, text=header, font=customtkinter.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=8, pady=6)

        content = customtkinter.CTkScrollableFrame(win, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        # Summary
        summary_lines = []
        summary_lines.append(f"Detected: {', '.join(detected) if detected else 'None'}")
        summary_lines.append(f"Confidence: {int(confidence*100)}%")
        if suggestion:
            summary_lines.append(f"Suggested action: {suggestion[0]} (confidence {int(suggestion[1]*100)}%)")
        summary_text = "\n".join(summary_lines)
        customtkinter.CTkLabel(content, text=summary_text, justify="left", anchor="w",
                               font=customtkinter.CTkFont(size=13, weight="bold")).pack(fill="x", padx=8, pady=(6, 8))

        # Technical details
        tech = "Details:\n" + ("\n".join(f"- {d}" for d in details) if details else "No extra details.")
        customtkinter.CTkLabel(content, text=textwrap.fill(tech, width=70), justify="left",
                               font=customtkinter.CTkFont(size=12)).pack(fill="x", padx=8, pady=(0, 10))

        # Actions
        actions = customtkinter.CTkFrame(content, fg_color="transparent")
        actions.pack(fill="x", padx=8, pady=(6, 12))

        def _use_suggested():
            if suggestion and suggestion[0]:
                op_name = suggestion[0]
                # best-effort mapping to decrypt_frame operation names
                mapping = {
                    "Base64 Decode": "From Base64",
                    "Base58 Decode": "Base58 Decode",
                    "Base85 Decode": "Base85 Decode",
                    "Hex Decode → then try AES/3DES": "From Hex",
                    "Base64 Decode → then try AES/3DES/ChaCha20": "From Base64",
                    "Manual selection required": None
                }
                op = mapping.get(op_name)
                if op is None:
                    if "Base64" in op_name:
                        op = "From Base64"
                    elif "Hex" in op_name:
                        op = "From Hex"
                    elif "AES" in op_name:
                        op = "AES Decrypt"
                    elif "3DES" in op_name or "DES" in op_name:
                        op = "DES Decrypt"
                if op:
                    try:
                        self.frame.add_recipe_step(op)
                        if self.app:
                            self.app.show_toast("Auto-Detect", f"Added '{op}' to the recipe.", toast_type="success")
                    except Exception:
                        if self.app:
                            self.app.show_toast("Auto-Detect", "Failed to auto-add operation.", toast_type="error")
                else:
                    if self.app:
                        self.app.show_toast("Auto-Detect", "No automatic mapping available for this suggestion.", toast_type="warning")
            else:
                if self.app:
                    self.app.show_toast("Auto-Detect", "No suggestion available. Please choose manually.", toast_type="warning")
            win.destroy()

        def _copy_details():
            text_for_copy = f"Detected: {', '.join(detected) if detected else 'None'}\nConfidence: {int(confidence*100)}%\n\n" + "\n".join(details)
            try:
                win.clipboard_clear()
                win.clipboard_append(text_for_copy)
                if self.app:
                    self.app.show_toast("Copied", "Detection details copied to clipboard.", toast_type="success")
            except Exception:
                try:
                    import pyperclip
                    pyperclip.copy(text_for_copy)
                    if self.app:
                        self.app.show_toast("Copied", "Detection details copied to clipboard.", toast_type="success")
                except Exception:
                    if self.app:
                        self.app.show_toast("Copy Failed", "Could not copy details to clipboard.", toast_type="error")

        btn_use = customtkinter.CTkButton(actions, text="Use Suggested", command=_use_suggested)
        btn_use.grid(row=0, column=0, padx=(0,8))
        btn_copy = customtkinter.CTkButton(actions, text="Copy Details", command=_copy_details)
        btn_copy.grid(row=0, column=1, padx=(8,8))
        btn_close = customtkinter.CTkButton(actions, text="Close", command=win.destroy)
        btn_close.grid(row=0, column=2, padx=(8,0))

        win.lift()
        win.focus_force()

    # ---------------------------
    # Public runner
    # ---------------------------
    def run(self):
        s = ""
        # prefer owner_frame._get_current_input() if exists
        get_input = getattr(self.frame, "_get_current_input", None)
        if callable(get_input):
            s = get_input()
        else:
            # fallback: try common attributes
            try:
                s = self.frame.input_textbox.get("1.0", "end-1c").strip()
            except Exception:
                s = ""
        if not s:
            if self.app:
                self.app.show_toast("Input Error", "The input field is empty.", toast_type="error")
            return
        # quick info
        if self.app:
            self.app.show_toast("Auto-Detect", "Analyzing input...", toast_type="info")
        result = self.detect(s)
        self._show_result_window(s, result)
