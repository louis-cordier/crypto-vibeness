#!/usr/bin/env python3
"""RSA-based Key Encapsulation Mechanism (KEM).

• RSA  : 1024-bit modulus, e = 65537, PKCS#1 v1.5 padding
• KEM  : encapsulate generates a random 128-bit session key,
         RSA-encrypts it with the peer's public key
• Keys : stored as JSON in .pub / .priv files per user
"""

import os
import json
import base64

# ── Miller-Rabin primality test ─────────────────────────────────────

def _is_probable_prime(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        # Random witness in [2, n-2]
        byte_len = max(1, (n.bit_length() + 7) // 8)
        a = int.from_bytes(os.urandom(byte_len), "big") % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    byte_len = bits // 8
    while True:
        n = int.from_bytes(os.urandom(byte_len), "big")
        n |= (1 << (bits - 1)) | 1          # force MSB and odd
        if _is_probable_prime(n):
            return n


# ── RSA key generation ──────────────────────────────────────────────

RSA_BITS = 1024
RSA_E = 65537


def generate_keypair(bits: int = RSA_BITS):
    """Return (public_key, private_key) as ((n,e), (n,d))."""
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % RSA_E == 0:
            continue
        break
    d = pow(RSA_E, -1, phi)
    return (n, RSA_E), (n, d)


# ── PKCS#1 v1.5 padding (type 2 — encryption) ──────────────────────

def _pkcs1_pad(message: bytes, key_size: int) -> bytes:
    max_msg = key_size - 11
    if len(message) > max_msg:
        raise ValueError(f"Message too long ({len(message)} > {max_msg})")
    pad_len = key_size - len(message) - 3
    padding = bytearray()
    while len(padding) < pad_len:
        b = os.urandom(1)
        if b != b"\x00":
            padding.extend(b)
    return b"\x00\x02" + bytes(padding) + b"\x00" + message


def _pkcs1_unpad(padded: bytes) -> bytes:
    if len(padded) < 11 or padded[0:2] != b"\x00\x02":
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    try:
        sep = padded.index(b"\x00", 2)
    except ValueError:
        raise ValueError("No separator found in PKCS#1 padding")
    return padded[sep + 1:]


# ── RSA encrypt / decrypt ──────────────────────────────────────────

def rsa_encrypt(plaintext: bytes, public_key: tuple[int, int]) -> bytes:
    n, e = public_key
    key_size = (n.bit_length() + 7) // 8
    padded = _pkcs1_pad(plaintext, key_size)
    m = int.from_bytes(padded, "big")
    c = pow(m, e, n)
    return c.to_bytes(key_size, "big")


def rsa_decrypt(ciphertext: bytes, private_key: tuple[int, int]) -> bytes:
    n, d = private_key
    key_size = (n.bit_length() + 7) // 8
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    padded = m.to_bytes(key_size, "big")
    return _pkcs1_unpad(padded)


# ── KEM (Key Encapsulation Mechanism) ───────────────────────────────

def encapsulate(public_key: tuple[int, int]) -> tuple[bytes, bytes]:
    """Generate a random 128-bit session key and RSA-encrypt it.
    Returns (ciphertext, session_key)."""
    session_key = os.urandom(16)
    ciphertext = rsa_encrypt(session_key, public_key)
    return ciphertext, session_key


def decapsulate(ciphertext: bytes, private_key: tuple[int, int]) -> bytes:
    """Decrypt KEM ciphertext → 128-bit session key."""
    return rsa_decrypt(ciphertext, private_key)


# ── Key file I/O (.pub / .priv as JSON) ────────────────────────────

def save_public_key(filepath: str, public_key: tuple[int, int]):
    n, e = public_key
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({"n": hex(n), "e": e}, f)


def save_private_key(filepath: str, private_key: tuple[int, int]):
    n, d = private_key
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({"n": hex(n), "d": hex(d)}, f)


def load_public_key(filepath: str) -> tuple[int, int]:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return int(data["n"], 16), data["e"]


def load_private_key(filepath: str) -> tuple[int, int]:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return int(data["n"], 16), int(data["d"], 16)


# ── base64 helpers ──────────────────────────────────────────────────

def ct_to_b64(ct: bytes) -> str:
    return base64.b64encode(ct).decode()


def ct_from_b64(b64: str) -> bytes:
    return base64.b64decode(b64)


def pubkey_to_dict(public_key: tuple[int, int]) -> dict:
    """Serialize public key for JSON transport."""
    n, e = public_key
    return {"n": hex(n), "e": e}


def pubkey_from_dict(d: dict) -> tuple[int, int]:
    """Deserialize public key from JSON transport."""
    return int(d["n"], 16), d["e"]


# ── self-test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import time

    print("Generating RSA-1024 keypair …", end=" ", flush=True)
    t0 = time.time()
    pub, priv = generate_keypair()
    print(f"done in {time.time() - t0:.2f}s")
    print(f"  n  = {pub[0].bit_length()} bits")
    print(f"  e  = {pub[1]}")

    # Test encrypt / decrypt
    msg = b"Hello, RSA!"
    ct = rsa_encrypt(msg, pub)
    pt = rsa_decrypt(ct, priv)
    assert pt == msg
    print(f"✅ RSA encrypt/decrypt: {msg!r}")

    # Test KEM
    ct, session_key = encapsulate(pub)
    recovered = decapsulate(ct, priv)
    assert recovered == session_key
    print(f"✅ KEM: session key = {session_key.hex()}")

    # Test file I/O
    save_public_key("/tmp/test_kem.pub", pub)
    save_private_key("/tmp/test_kem.priv", priv)
    pub2 = load_public_key("/tmp/test_kem.pub")
    priv2 = load_private_key("/tmp/test_kem.priv")
    assert pub2 == pub and priv2 == priv
    print("✅ Key save/load")
    os.remove("/tmp/test_kem.pub")
    os.remove("/tmp/test_kem.priv")

    # Test base64 + dict helpers
    d = pubkey_to_dict(pub)
    assert pubkey_from_dict(d) == pub
    print("✅ pubkey_to_dict / pubkey_from_dict")

    print("\n🎉 All KEM tests passed!")
