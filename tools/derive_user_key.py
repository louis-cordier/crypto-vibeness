#!/usr/bin/env python3
"""Derive and store symmetric key for a user from a passphrase.
Saves server-side key file 'user_keys_do_not_steal_plz.txt' and client key './users/<username>/key.txt'
Format (server file): username:pbkdf2:100000:salt_base64:key_base64
Client key.txt contains raw base64 key
"""
import argparse
import os
import base64
from pathlib import Path
from crypto_utils import derive_key

SERVER_FILE = 'user_keys_do_not_steal_plz.txt'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('username')
    p.add_argument('--passphrase', help='User passphrase (will prompt if omitted)')
    p.add_argument('--iterations', type=int, default=100000)
    p.add_argument('--key-len', type=int, default=16)
    args = p.parse_args()

    if not args.passphrase:
        import getpass
        args.passphrase = getpass.getpass('Passphrase: ')

    salt_b64, key = derive_key(args.passphrase, salt=None, iterations=args.iterations, key_len=args.key_len)
    key_b64 = base64.b64encode(key).decode('ascii')

    # write server file (append)
    line = f"{args.username}:pbkdf2:{args.iterations}:{salt_b64}:{key_b64}\n"
    with open(SERVER_FILE, 'a') as f:
        f.write(line)
    print('Wrote server key to', SERVER_FILE)

    # write client key file
    userdir = Path('users') / args.username
    userdir.mkdir(parents=True, exist_ok=True)
    with open(userdir / 'key.txt', 'w') as f:
        f.write(key_b64)
    print('Wrote client key to', userdir / 'key.txt')

if __name__ == '__main__':
    main()
