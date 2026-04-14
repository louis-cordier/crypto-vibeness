#!/usr/bin/env python3
"""Simple multi-room chat server for 'Jour 1 - 1ère partie : YOLO'.
Usage: python3 server.py --port 12345
"""
import argparse
import socket
import threading
import logging
import os
from datetime import datetime
import json

# Configuration
DEFAULT_PORT = 12345
LOG_DIR = "logs"
DEFAULT_ROOM = "general"
ADDRESS = "0.0.0.0"

os.makedirs(LOG_DIR, exist_ok=True)
logfile = os.path.join(LOG_DIR, f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt")
logging.basicConfig(level=logging.INFO, filename=logfile, format='%(asctime)s %(message)s')

# Server state
clients_lock = threading.Lock()
clients = {}  # socket -> {username, addr, room}
usernames = set()
rooms = {DEFAULT_ROOM: { 'password': None, 'members': set() }}

COLORS = ["red","green","yellow","blue","magenta","cyan","white"]


def assign_color(name, addr):
    # Deterministic color based on username+addr
    h = hash(f"{name}:{addr[0]}:{addr[1]}")
    return COLORS[abs(h) % len(COLORS)]


def log_event(msg):
    print(msg)
    logging.info(msg)


def send_line(sock, line):
    try:
        sock.sendall((line + "\n").encode())
    except Exception:
        pass


def broadcast(room, line, exclude_sock=None):
    with clients_lock:
        members = list(rooms.get(room, {}).get('members', []))
    for s in members:
        if s is exclude_sock:
            continue
        send_line(s, line)


def handle_client(conn, addr):
    try:
        send_line(conn, "WELCOME to Crypto Vibeness chat. Please enter your username:")
        username = None
        fileobj = conn.makefile('r')
        # choose username
        while True:
            line = fileobj.readline()
            if not line:
                return
            candidate = line.strip()
            if not candidate:
                send_line(conn, "USERNAME_EMPTY")
                continue
            with clients_lock:
                if candidate in usernames:
                    send_line(conn, "USERNAME_TAKEN")
                    continue
                else:
                    username = candidate
                    usernames.add(username)
                    clients[conn] = {'username': username, 'addr': addr, 'room': DEFAULT_ROOM}
                    rooms[DEFAULT_ROOM]['members'].add(conn)
                    break
        color = assign_color(username, addr)
        send_line(conn, f"USERNAME_OK {username} {color} {DEFAULT_ROOM}")
        log_event(f"CONNECT {username} {addr}")
        broadcast(DEFAULT_ROOM, f"[SYSTEM] {username} has joined {DEFAULT_ROOM} (color={color})")

        # Handle incoming messages
        for raw in fileobj:
            msg = raw.rstrip('\n')
            if not msg:
                continue
            if msg.startswith('/'):
                # command
                parts = msg.split()
                cmd = parts[0].lower()
                if cmd == '/quit':
                    send_line(conn, 'BYE')
                    break
                elif cmd == '/rooms':
                    # list rooms, mark locked
                    with clients_lock:
                        lst = []
                        for r, data in rooms.items():
                            locked = data.get('password') is not None
                            lst.append(r + (" [LOCKED]" if locked else ""))
                    send_line(conn, 'ROOMS ' + json.dumps(lst))
                elif cmd == '/create':
                    if len(parts) >= 2:
                        rname = parts[1]
                        pwd = parts[2] if len(parts) >=3 else None
                        with clients_lock:
                            if rname in rooms:
                                send_line(conn, f"ERROR Room {rname} already exists")
                            else:
                                rooms[rname] = {'password': pwd, 'members': set()}
                                send_line(conn, f"CREATED {rname} {'LOCKED' if pwd else 'OPEN'}")
                                log_event(f"ROOM_CREATE {rname} by {username} pwd={'YES' if pwd else 'NO'}")
                    else:
                        send_line(conn, "ERROR Usage: /create <room> [password]")
                elif cmd == '/join':
                    if len(parts) >= 2:
                        rname = parts[1]
                        pwd = parts[2] if len(parts) >=3 else None
                        with clients_lock:
                            if rname not in rooms:
                                send_line(conn, f"ERROR No such room {rname}")
                            else:
                                room = rooms[rname]
                                if room.get('password') and room.get('password') != pwd:
                                    send_line(conn, f"ERROR Wrong password for {rname}")
                                else:
                                    # move client
                                    old = clients[conn]['room']
                                    rooms[old]['members'].discard(conn)
                                    clients[conn]['room'] = rname
                                    rooms[rname]['members'].add(conn)
                                    send_line(conn, f"JOINED {rname}")
                                    broadcast(old, f"[SYSTEM] {username} left {old}")
                                    broadcast(rname, f"[SYSTEM] {username} joined {rname}")
                                    log_event(f"JOIN {username} {rname}")
                    else:
                        send_line(conn, "ERROR Usage: /join <room> [password]")
                elif cmd == '/leave':
                    with clients_lock:
                        old = clients[conn]['room']
                        if old != DEFAULT_ROOM:
                            rooms[old]['members'].discard(conn)
                            clients[conn]['room'] = DEFAULT_ROOM
                            rooms[DEFAULT_ROOM]['members'].add(conn)
                            send_line(conn, f"LEFT {old}")
                            broadcast(old, f"[SYSTEM] {username} left {old}")
                            broadcast(DEFAULT_ROOM, f"[SYSTEM] {username} joined {DEFAULT_ROOM}")
                        else:
                            send_line(conn, "ERROR Already in general")
                else:
                    send_line(conn, 'ERROR Unknown command')
            else:
                # regular message -> broadcast to current room with timestamp
                with clients_lock:
                    room = clients[conn]['room']
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                line = f"MSG {room} {ts} {username}: {msg}"
                broadcast(room, line)
                log_event(f"MSG {room} {username}: {msg}")
    except Exception as e:
        log_event(f"EXCEPTION {e}")
    finally:
        # cleanup
        with clients_lock:
            info = clients.pop(conn, None)
            if info:
                uname = info['username']
                usernames.discard(uname)
                room = info['room']
                rooms.get(room, {}).get('members', set()).discard(conn)
                broadcast(room, f"[SYSTEM] {uname} disconnected")
                log_event(f"DISCONNECT {uname} {addr}")
        try:
            conn.close()
        except Exception:
            pass


def serve(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ADDRESS, port))
    sock.listen()
    log_event(f"SERVER_STARTED port={port}")
    print(f"Server listening on port {port}")
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print('Shutting down')
    finally:
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    serve(args.port)
