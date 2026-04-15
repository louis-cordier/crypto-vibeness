#!/usr/bin/env python3
"""TEA block cipher in CBC mode with PBKDF2 key derivation.

• TEA  : 64-bit blocks, 128-bit key, 32 Feistel rounds
• CBC  : random 8-byte IV prepended to ciphertext, PKCS7 padding
• KDF  : PBKDF2-HMAC-SHA256, 128-bit output, per-user salt
"""

import hashlib
import os
import struct
import base64

# ── TEA core (single 64-bit block) ─────────────────────────────────

DELTA = 0x9E3779B9
ROUNDS = 32
MASK32 = 0xFFFFFFFF


def _tea_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 8-byte block with a 16-byte key using TEA."""
    v0, v1 = struct.unpack(">II", block)
    k0, k1, k2, k3 = struct.unpack(">IIII", key)
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & MASK32
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK32
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK32
    return struct.pack(">II", v0, v1)


def _tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt one 8-byte block with a 16-byte key using TEA."""
    v0, v1 = struct.unpack(">II", block)
    k0, k1, k2, k3 = struct.unpack(">IIII", key)
    total = (DELTA * ROUNDS) & MASK32
    for _ in range(ROUNDS):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK32
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK32
        total = (total - DELTA) & MASK32
    return struct.pack(">II", v0, v1)


# ── CBC mode ────────────────────────────────────────────────────────

BLOCK_SIZE = 8  # TEA operates on 64-bit (8-byte) blocks


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with TEA-CBC. Returns IV (8 bytes) + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    padded = _pkcs7_pad(plaintext)
    prev = iv
    out = bytearray(iv)
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = _xor_bytes(block, prev)
        enc = _tea_encrypt_block(xored, key)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt TEA-CBC. Expects IV (8 bytes) + ciphertext."""
    if len(ciphertext) < BLOCK_SIZE * 2:
        raise ValueError("Ciphertext too short")
    iv = ciphertext[:BLOCK_SIZE]
    data = ciphertext[BLOCK_SIZE:]
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length not aligned")
    prev = iv
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        dec = _tea_decrypt_block(block, key)
        out.extend(_xor_bytes(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(out))


# ── Key derivation ──────────────────────────────────────────────────

KDF_ITERATIONS = 100_000


def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte (128-bit) salt."""
    return os.urandom(16)


def derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a 128-bit (16-byte) key from a secret using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt,
                               KDF_ITERATIONS, dklen=16)


# ── base64 helpers ──────────────────────────────────────────────────

def key_to_b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def key_from_b64(b64: str) -> bytes:
    return base64.b64decode(b64)


def encrypt_b64(plaintext: str, key: bytes) -> str:
    """Encrypt a UTF-8 string, return base64-encoded ciphertext."""
    return base64.b64encode(encrypt(plaintext.encode("utf-8"), key)).decode()


def decrypt_b64(b64_ciphertext: str, key: bytes) -> str:
    """Decrypt a base64-encoded ciphertext, return UTF-8 string."""
    return decrypt(base64.b64decode(b64_ciphertext), key).decode("utf-8")


# ── self-test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    salt = generate_salt()
    key = derive_key("MySecret123!", salt)
    print(f"Salt : {key_to_b64(salt)}")
    print(f"Key  : {key_to_b64(key)} ({len(key)*8} bits)")

    for msg in ["Hello!", "A", "12345678", "Unicode: é€🔒", "x" * 200]:
        ct = encrypt_b64(msg, key)
        pt = decrypt_b64(ct, key)
        assert pt == msg, f"FAIL: {msg!r}"
        print(f"✅ '{msg[:30]}...' → {len(ct)} chars base64")

    print("\n🎉 All TEA-CBC tests passed!")
