#!/usr/bin/env python3
"""Multi-user chat server (IRC-like, no auth, no encryption)."""

import socket
import threading
import json
import sys
import hashlib
import datetime

DEFAULT_PORT = 5555

COLORS = [
    "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m",
    "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m",
]
RESET = "\033[0m"


class ChatServer:
    def __init__(self, port):
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # username -> {socket, address, room, color}
        self.rooms = {"general": {"password": None, "users": set()}}
        self.lock = threading.Lock()

        now = datetime.datetime.now()
        log_filename = f"log_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        self.log_file = open(log_filename, "a", encoding="utf-8")

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _color_for(username: str) -> str:
        h = int(hashlib.md5(username.encode()).hexdigest(), 16)
        return COLORS[h % len(COLORS)]

    def _log(self, message: str):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {message}"
        print(entry)
        self.log_file.write(entry + "\n")
        self.log_file.flush()

    @staticmethod
    def _send(sock: socket.socket, data: dict):
        try:
            sock.sendall((json.dumps(data) + "\n").encode("utf-8"))
        except OSError:
            pass

    def _broadcast(self, room: str, data: dict, *, exclude: str | None = None):
        with self.lock:
            users = list(self.rooms.get(room, {}).get("users", []))
        for u in users:
            if u == exclude:
                continue
            with self.lock:
                info = self.clients.get(u)
            if info:
                self._send(info["socket"], data)

    # ── client lifecycle ─────────────────────────────────────────────

    def _read_line(self, sock: socket.socket, buf: list[str]) -> str | None:
        """Block until a full JSON line is available; return it."""
        while "\n" not in buf[0]:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf[0] += chunk.decode("utf-8")
        line, buf[0] = buf[0].split("\n", 1)
        return line

    def _register(self, sock, addr, buf) -> str | None:
        """Username negotiation – returns username or None on disconnect."""
        self._send(sock, {"type": "prompt", "content": "Choose your username: "})
        while True:
            line = self._read_line(sock, buf)
            if line is None:
                return None
            try:
                name = json.loads(line).get("content", "").strip()
            except json.JSONDecodeError:
                continue
            if not name:
                self._send(sock, {"type": "error",
                                  "content": "Username cannot be empty. Try again: "})
                continue
            with self.lock:
                if name in self.clients:
                    self._send(sock, {"type": "error",
                                      "content": f"Username '{name}' is already taken. Try again: "})
                    continue
                color = self._color_for(name)
                self.clients[name] = {"socket": sock, "address": addr,
                                      "room": "general", "color": color}
                self.rooms["general"]["users"].add(name)
            return name

    def handle_client(self, sock, addr):
        buf = [""]
        username = None
        try:
            username = self._register(sock, addr, buf)
            if username is None:
                return
            color = self.clients[username]["color"]
            self._log(f"{username} connected from {addr}")
            self._send(sock, {"type": "welcome", "username": username,
                              "color": color,
                              "content": f"Welcome {username}! You are in room 'general'. Type /help for commands."})
            self._broadcast("general",
                            {"type": "system", "content": f"{username} has joined the room."},
                            exclude=username)
            self._log(f"{username} joined room 'general'")

            while True:
                line = self._read_line(sock, buf)
                if line is None:
                    break
                try:
                    content = json.loads(line).get("content", "")
                except json.JSONDecodeError:
                    continue
                self._process(username, content)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            if username:
                self._disconnect(username)

    # ── message processing ───────────────────────────────────────────

    def _process(self, username: str, content: str):
        if content.startswith("/"):
            self._command(username, content)
        else:
            with self.lock:
                info = self.clients.get(username)
            if not info:
                return
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._broadcast(info["room"], {
                "type": "message", "username": username,
                "content": content, "timestamp": ts, "color": info["color"],
            })
            self._log(f"[{info['room']}] {username}: {content}")

    def _command(self, username: str, text: str):
        parts = text.split()
        cmd = parts[0].lower()
        sock = self.clients[username]["socket"]

        if cmd == "/help":
            self._send(sock, {"type": "system", "content":
                "Commands:\n"
                "  /rooms                      – List all rooms\n"
                "  /create <name> [password]    – Create a room\n"
                "  /join <name> [password]      – Join a room\n"
                "  /leave                       – Back to general\n"
                "  /who                         – Users in current room\n"
                "  /quit                        – Disconnect"})

        elif cmd == "/rooms":
            with self.lock:
                rlist = [{"name": n, "protected": r["password"] is not None,
                          "count": len(r["users"])}
                         for n, r in self.rooms.items()]
            self._send(sock, {"type": "room_list", "rooms": rlist})

        elif cmd == "/create":
            if len(parts) < 2:
                self._send(sock, {"type": "error",
                                  "content": "Usage: /create <name> [password]"})
                return
            name = parts[1]
            pwd = parts[2] if len(parts) > 2 else None
            with self.lock:
                if name in self.rooms:
                    self._send(sock, {"type": "error",
                                      "content": f"Room '{name}' already exists."})
                    return
                self.rooms[name] = {"password": pwd, "users": set()}
            tag = " (password-protected)" if pwd else ""
            self._send(sock, {"type": "system",
                              "content": f"Room '{name}' created{tag}."})
            self._log(f"{username} created room '{name}'{tag}")

        elif cmd == "/join":
            if len(parts) < 2:
                self._send(sock, {"type": "error",
                                  "content": "Usage: /join <name> [password]"})
                return
            target = parts[1]
            pwd = parts[2] if len(parts) > 2 else None
            with self.lock:
                if target not in self.rooms:
                    self._send(sock, {"type": "error",
                                      "content": f"Room '{target}' does not exist."})
                    return
                room_pwd = self.rooms[target]["password"]
                if room_pwd is not None and room_pwd != pwd:
                    self._send(sock, {"type": "error",
                                      "content": "Incorrect password."})
                    self._log(f"{username} failed to join '{target}' (wrong password)")
                    return
                old = self.clients[username]["room"]
                if old == target:
                    self._send(sock, {"type": "error",
                                      "content": f"You are already in '{target}'."})
                    return
                self.rooms[old]["users"].discard(username)
                self.rooms[target]["users"].add(username)
                self.clients[username]["room"] = target
            self._broadcast(old, {"type": "system",
                                  "content": f"{username} has left the room."})
            self._send(sock, {"type": "system",
                              "content": f"You joined room '{target}'."})
            self._broadcast(target, {"type": "system",
                                     "content": f"{username} has joined the room."},
                            exclude=username)
            self._log(f"{username} moved from '{old}' to '{target}'")

        elif cmd == "/leave":
            with self.lock:
                cur = self.clients[username]["room"]
                if cur == "general":
                    self._send(sock, {"type": "error",
                                      "content": "You are already in 'general'."})
                    return
                self.rooms[cur]["users"].discard(username)
                self.rooms["general"]["users"].add(username)
                self.clients[username]["room"] = "general"
            self._broadcast(cur, {"type": "system",
                                  "content": f"{username} has left the room."})
            self._send(sock, {"type": "system",
                              "content": "You are back in room 'general'."})
            self._broadcast("general", {"type": "system",
                                        "content": f"{username} has joined the room."},
                            exclude=username)
            self._log(f"{username} left '{cur}' → 'general'")

        elif cmd == "/who":
            with self.lock:
                room = self.clients[username]["room"]
                users = sorted(self.rooms[room]["users"])
            self._send(sock, {"type": "system",
                              "content": f"Users in '{room}': {', '.join(users)}"})

        elif cmd == "/quit":
            self._send(sock, {"type": "quit", "content": "Goodbye!"})
            self._disconnect(username)

        else:
            self._send(sock, {"type": "error",
                              "content": f"Unknown command: {cmd}. Type /help."})

    # ── disconnect ───────────────────────────────────────────────────

    def _disconnect(self, username: str):
        with self.lock:
            info = self.clients.pop(username, None)
            if info is None:
                return
            room = info["room"]
            self.rooms.get(room, {}).get("users", set()).discard(username)
        try:
            info["socket"].close()
        except OSError:
            pass
        self._broadcast(room, {"type": "system",
                               "content": f"{username} has left the chat."})
        self._log(f"{username} disconnected")

    # ── main loop ────────────────────────────────────────────────────

    def start(self):
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen()
        self._log(f"Server listening on port {self.port}")
        try:
            while True:
                csock, addr = self.server_socket.accept()
                self._log(f"New connection from {addr}")
                threading.Thread(target=self.handle_client,
                                 args=(csock, addr), daemon=True).start()
        except KeyboardInterrupt:
            self._log("Server shutting down")
        finally:
            self.server_socket.close()
            self.log_file.close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    ChatServer(port).start()
