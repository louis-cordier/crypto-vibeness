#!/usr/bin/env python3
"""Crypto helpers: key derivation (PBKDF2-HMAC-SHA256), AES-CBC encryption with PKCS7 padding.
Functions:
 - derive_key(passphrase, salt=None, iterations=100000, key_len=16)
 - encrypt_message(key_bytes, plaintext) -> base64(iv + ciphertext)
 - decrypt_message(key_bytes, b64_iv_ciphertext) -> plaintext (str) or raises
"""
import base64
import hashlib
import secrets

try:
    from Crypto.Cipher import AES
except Exception:
    AES = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except Exception:
    Cipher = None


def _pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data):
    if not data:
        raise ValueError('Invalid padding')
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError('Invalid padding')
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError('Invalid padding bytes')
    return data[:-pad_len]


def derive_key(passphrase, salt=None, iterations=100000, key_len=16):
    """Derive key via PBKDF2-HMAC-SHA256.
    Returns (salt_b64, key_bytes)
    If salt is None, a random 12-byte (96-bit) salt is generated.
    """
    if salt is None:
        salt_bytes = secrets.token_bytes(12)
    else:
        if isinstance(salt, str):
            salt_bytes = base64.b64decode(salt)
        else:
            salt_bytes = salt
    key = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt_bytes, iterations, dklen=key_len)
    salt_b64 = base64.b64encode(salt_bytes).decode('ascii')
    return salt_b64, key


def encrypt_message(key_bytes, plaintext):
    """Encrypt plaintext (str) with AES-CBC using key_bytes (bytes).
    Returns base64(iv + ciphertext)
    """
    data = plaintext.encode('utf-8')
    iv = secrets.token_bytes(16)
    padded = _pkcs7_pad(data, 16)
    if AES is not None:
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        ct = cipher.encrypt(padded)
    elif Cipher is not None:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
    else:
        raise SystemExit('No AES backend available: install pycryptodome or cryptography')
    return base64.b64encode(iv + ct).decode('ascii')


def decrypt_message(key_bytes, b64_iv_ct):
    """Decrypt base64(iv+ciphertext) and return plaintext string."""
    raw = base64.b64decode(b64_iv_ct)
    if len(raw) < 16:
        raise ValueError('Ciphertext too short')
    iv = raw[:16]
    ct = raw[16:]
    if AES is not None:
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ct)
    elif Cipher is not None:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
    else:
        raise SystemExit('No AES backend available: install pycryptodome or cryptography')
    data = _pkcs7_unpad(padded)
    return data.decode('utf-8')
