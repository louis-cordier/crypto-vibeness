#!/usr/bin/env python3
"""Simple console chat client for the Crypto Vibeness server.
Usage: python3 client.py --host 127.0.0.1 --port 12345
Commands:
  /rooms                list rooms
  /create <room> [pwd]  create room
  /join <room> [pwd]    join room
  /leave                go back to general
  /quit                 quit
"""
import argparse
import socket
import threading
import sys
import json

COLORS_MAP = {
    'red': '\u001b[31m',
    'green': '\u001b[32m',
    'yellow': '\u001b[33m',
    'blue': '\u001b[34m',
    'magenta': '\u001b[35m',
    'cyan': '\u001b[36m',
    'white': '\u001b[37m',
}
RESET = '\u001b[0m'


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
            # USERNAME_OK <username> <color> <room>
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


def stdin_loop(sock):
    try:
        while True:
            line = input()
            if not line:
                continue
            sock.sendall((line + '\n').encode())
            if line.strip() == '/quit':
                break
    except EOFError:
        sock.sendall(("/quit\n").encode())
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
    stdin_loop(s)
    s.close()
