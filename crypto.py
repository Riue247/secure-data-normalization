# crypto.py

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import sys
import os

# Optional: Excel to CSV-style line formatter
try:
    import openpyxl
except ImportError:
    openpyxl = None

# 🔐 Hardcoded demo key and IV (replace with secure key/IV later)
KEY = b'0123456789ABCDEF0123456789ABCDEF'  # 32 bytes = AES-256
IV = b'ABCDEF0123456789'  # 16 bytes = 128-bit IV for CBC mode

def pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt(plaintext: bytes) -> str:
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(plaintext)
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(ciphertext_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded).decode('utf-8')

def sha256_file(input_path, output_path):
    with open(input_path, "rb") as f:
        content = f.read()
        hash_value = hashlib.sha256(content).hexdigest()

    with open(output_path, "w") as f:
        f.write(hash_value)

# 🔍 Extract structured lines from .xlsx
def xlsx_to_lines(path):
    if openpyxl is None:
        raise ImportError("openpyxl is not installed. Cannot read Excel files.")
    wb = openpyxl.load_workbook(path)
    sheet = wb.active
    headers = [str(cell.value).strip() for cell in sheet[1]]
    lines = []
    for row in sheet.iter_rows(min_row=2, values_only=True):
        items = zip(headers, row)
        line = ", ".join(f"{key}: {value}" for key, value in items if value is not None)
        lines.append(line)
    return lines

# Command-line mode for Racket or shell to use
if __name__ == "__main__":
    mode = sys.argv[1]
    input_file = sys.argv[2]

    if mode == "hash-string":
        password = input_file
        output_file = sys.argv[3] if len(sys.argv) > 3 else "hashed.txt"
        result = hashlib.sha256(password.encode('utf-8')).hexdigest()
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(result)
        print("✅ Python hash-string: done")
        sys.exit(0)

    output_file = sys.argv[3]

    if mode == "encrypt":
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        result = encrypt(content.encode('utf-8'))

    elif mode == "decrypt":
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        result = decrypt(content)

    elif mode == "hash":
        sha256_file(input_file, output_file)
        result = None

    elif mode == "verify":
        # Step 1: Decrypt file
        with open(input_file, 'r', encoding='utf-8') as f:
            encrypted_content = f.read()

        decrypted = decrypt(encrypted_content)

        # Step 2: Hash decrypted log
        current_hash = hashlib.sha256(decrypted.encode('utf-8')).hexdigest()

        # Step 3: Compare with saved hash
        with open(output_file, "r", encoding='utf-8') as f:
            saved_hash = f.read().strip()

        if current_hash == saved_hash:
            print("✅ Audit log is intact. No tampering detected.")
        else:
            print("❌ Audit log hash mismatch. Possible tampering detected.")

        sys.exit(0)  # exit after verifying (prevents accidental writes)

    elif mode == "xlsx-to-lines":
        lines = xlsx_to_lines(input_file)
        with open(output_file, "w", encoding='utf-8') as f:
            for line in lines:
                f.write(line + "\n")
                print(f"📄 Parsed Row: {line}")
        print("✅ Extracted lines from Excel.")
        result = None


    else:
        raise ValueError("Mode must be 'encrypt', 'decrypt', 'hash', 'verify', 'hash-string', or 'xlsx-to-lines'")

    if result is not None:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)


