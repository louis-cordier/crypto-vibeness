#!/usr/bin/env python3
"""Secure client: encrypts outgoing messages with AES-CBC using user's derived symmetric key.
Usage: python3 client_secure.py --host 127.0.0.1 --port 12345

Notes:
- Requires crypto_utils.py in project root.
- Each user should have ./users/<username>/key.txt containing base64 key (create with tools/derive_user_key.py)
- On receiving messages, client attempts to load sender's key from ./users/<sender>/key.txt to decrypt.
"""
import argparse
import socket
import threading
import sys
import json
import base64
from pathlib import Path
from crypto_utils import encrypt_message, decrypt_message


def load_key_for_user(username):
    p = Path('users') / username / 'key.txt'
    if not p.exists():
        return None
    return base64.b64decode(p.read_text().strip())


def recv_loop(sock):
    f = sock.makefile('r')
    while True:
        line = f.readline()
        if not line:
            print('\n[Disconnected from server]')
            sys.exit(0)
        line = line.rstrip('\n')
        if line.startswith('MSG '):
            # MSG room timestamp username: msg
            parts = line.split(' ', 4)
            if len(parts) >=5:
                _, room, ts, rest = parts[0], parts[1], parts[2], parts[4]
                # rest contains username: message
                if ':' in rest:
                    sender, msg = rest.split(':',1)
                    sender = sender.strip()
                    msg = msg.strip()
                    key = load_key_for_user(sender)
                    if key:
                        try:
                            plain = decrypt_message(key, msg)
                            print(f"[{ts}] {sender}: {plain}")
                            continue
                        except Exception:
                            pass
                print(f"[{ts}] {rest}")
            else:
                print(line)
        elif line.startswith('ROOMS '):
            payload = line[len('ROOMS '):]
            try:
                lst = json.loads(payload)
                print('\nAvailable rooms:')
                for r in lst:
                    if '[LOCKED]' in r:
                        print(f"  - {r} \u26BF (locked)")
                    else:
                        print(f"  - {r}")
                print('')
            except Exception:
                print('ROOMS ' + payload)
        elif line.startswith('WELCOME'):
            print(line)
        elif line.startswith('USERNAME_OK'):
            parts = line.split(' ', 3)
            if len(parts) >=4:
                _, username, color, room = parts
                print(f"Connected as {username} in room {room}. Assigned color: {color}")
            else:
                print(line)
        elif line.startswith('USERNAME_TAKEN'):
            print('That username is already taken, try another:')
        elif line.startswith('CREATED '):
            print(line)
        elif line.startswith('JOINED '):
            print(line)
        elif line.startswith('LEFT '):
            print(line)
        elif line.startswith('ERROR'):
            print(line)
        elif line.startswith('BYE'):
            print('Goodbye')
            sys.exit(0)
        else:
            print(line)


def stdin_loop(sock, username):
    try:
        key = load_key_for_user(username)
        if not key:
            print('No local key found for', username, '— messages will be sent plaintext. Create one with tools/derive_user_key.py')
        while True:
            line = input()
            if not line:
                continue
            # Commands start with /
            if line.startswith('/'):
                sock.sendall((line + '\n').encode())
                if line.strip() == '/quit':
                    break
                continue
            # encrypt message if key available
            if key:
                try:
                    enc = encrypt_message(key, line)
                    send = enc
                except Exception:
                    send = line
            else:
                send = line
            sock.sendall((send + '\n').encode())
            if send.strip() == '/quit':
                break
    except EOFError:
        try:
            sock.sendall(('/quit\n').encode())
        except Exception:
            pass
    except Exception:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=12345)
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))
    # start receiver
    t = threading.Thread(target=recv_loop, args=(s,), daemon=True)
    t.start()

    # initial username prompt
    f = s.makefile('r')
    # Read initial welcome
    while True:
        line = f.readline()
        if not line:
            print('No response from server')
            sys.exit(1)
        line=line.rstrip('\n')
        if line.startswith('WELCOME'):
            print(line)
            break
    # send username
    username = input('Username: ').strip()
    s.sendall((username + '\n').encode())
    # wait for response: either USERNAME_OK or USERNAME_TAKEN
    while True:
        line = f.readline()
        if not line:
            print('Server closed')
            sys.exit(1)
        line=line.rstrip('\n')
        if line.startswith('USERNAME_TAKEN'):
            username = input('Username (another): ').strip()
            s.sendall((username + '\n').encode())
            continue
        if line.startswith('USERNAME_OK'):
            print(line)
            break
        else:
            print(line)

    # now enter stdin loop
    print('Type messages or commands. /rooms /create /join /leave /quit')
    stdin_loop(s, username)
    s.close()
