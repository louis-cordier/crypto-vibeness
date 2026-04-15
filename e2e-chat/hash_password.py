#!/usr/bin/env python3
"""Modern password hashing script using bcrypt."""

import sys
import os
import base64
import bcrypt

_BCRYPT_B64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _bcrypt_b64_decode(s: str) -> bytes:
    """Decode bcrypt's modified Radix-64 to raw bytes."""
    vals = [_BCRYPT_B64.index(c) for c in s]
    out = bytearray()
    i = 0
    while i < len(vals):
        n = min(4, len(vals) - i)
        chunk = vals[i:i + n] + [0] * (4 - min(4, len(vals) - i))
        out.append(((chunk[0] << 2) | (chunk[1] >> 4)) & 0xFF)
        if n >= 3:
            out.append((((chunk[1] & 0xF) << 4) | (chunk[2] >> 2)) & 0xFF)
        if n >= 4:
            out.append((((chunk[2] & 0x3) << 6) | chunk[3]) & 0xFF)
        i += 4
    return bytes(out)


def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <username> <password>")

    username = sys.argv[1]
    password = sys.argv[2].encode("utf-8")

    # Work factor (cost) – 2^12 = 4096 iterations
    cost = 12

    # bcrypt generates a 16-byte (128 bits > 96 bits) cryptographically
    # secure salt internally via os.urandom
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(password, salt)

    # Parse bcrypt output: $2b$12$<22-char salt><31-char hash>
    parts = hashed.decode().split("$")
    algo = f"bcrypt-{parts[1]}"     # bcrypt-2b
    payload = parts[3]
    raw_salt = _bcrypt_b64_decode(payload[:22])   # 16 bytes
    raw_hash = _bcrypt_b64_decode(payload[22:])   # 23 bytes

    salt_b64 = base64.b64encode(raw_salt).decode()
    hash_b64 = base64.b64encode(raw_hash).decode()

    print(f"{username}:{algo}:cost={cost}:{salt_b64}:{hash_b64}")


if __name__ == "__main__":
    main()
