#!/usr/bin/env python3
"""Multi-user chat server with MD5 password authentication."""

import socket
import threading
import json
import sys
import hashlib
import hmac
import base64
import datetime
import math
import re
import os
import string

DEFAULT_PORT = 5555
PASSWORD_FILE = "this_is_safe.txt"
RULES_FILE = "password_rules.json"

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

        self.passwords = self._load_passwords()
        self.password_rules = self._load_rules()

    # ── password storage ─────────────────────────────────────────────

    @staticmethod
    def _generate_salt() -> str:
        """Generate a random 16-byte salt, encoded in base64."""
        return base64.b64encode(os.urandom(16)).decode()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """MD5 hash of salt+password, encoded in base64."""
        md5 = hashlib.md5((salt + password).encode()).digest()
        return base64.b64encode(md5).decode()

    def _load_passwords(self) -> dict[str, dict]:
        """Load username:{salt, hash} from this_is_safe.txt."""
        pw = {}
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) == 3:
                            user, salt, hashed = parts
                            pw[user] = {"salt": salt, "hash": hashed}
        return pw

    def _save_passwords(self):
        with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
            for user, data in self.passwords.items():
                f.write(f"{user}:{data['salt']}:{data['hash']}\n")

    def _verify_password(self, username: str, password: str) -> bool:
        """Constant-time password comparison."""
        data = self.passwords.get(username)
        if not data:
            return False
        candidate = self._hash_password(password, data["salt"])
        return hmac.compare_digest(data["hash"], candidate)

    # ── password rules ───────────────────────────────────────────────

    def _load_rules(self) -> list[dict]:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("rules", [])
        return []

    def _check_password_rules(self, password: str) -> list[str]:
        """Return list of violated rule descriptions."""
        violations = []
        for rule in self.password_rules:
            rtype = rule["type"]
            if rtype == "min_length":
                if len(password) < rule["value"]:
                    violations.append(rule["description"])
            elif rtype == "regex":
                if not re.search(rule["value"], password):
                    violations.append(rule["description"])
        return violations

    @staticmethod
    def _password_entropy(password: str) -> float:
        """Calculate Shannon entropy in bits."""
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"[0-9]", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 32
        if charset_size == 0:
            return 0.0
        return len(password) * math.log2(charset_size)

    @staticmethod
    def _strength_label(entropy: float) -> str:
        if entropy < 28:
            return "🔴 Très faible"
        elif entropy < 36:
            return "🟠 Faible"
        elif entropy < 50:
            return "🟡 Moyen"
        elif entropy < 65:
            return "🟢 Fort"
        else:
            return "🟢🟢 Très fort"

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
        """Username + password authentication – returns username or None."""
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
                                      "content": f"Username '{name}' is already connected. Try again: "})
                    continue

            # ── Known user → login ──
            if name in self.passwords:
                self._send(sock, {"type": "auth_prompt",
                                  "content": f"Password for '{name}': "})
                line = self._read_line(sock, buf)
                if line is None:
                    return None
                try:
                    pwd = json.loads(line).get("content", "")
                except json.JSONDecodeError:
                    continue
                if not self._verify_password(name, pwd):
                    self._send(sock, {"type": "error",
                                      "content": "Wrong password. Try again.\n"})
                    self._log(f"Failed login attempt for '{name}' from {addr}")
                    self._send(sock, {"type": "prompt",
                                      "content": "Choose your username: "})
                    continue
                self._log(f"'{name}' authenticated successfully from {addr}")

            # ── New user → register ──
            else:
                self._send(sock, {"type": "system",
                                  "content": f"New user '{name}'. Let's create your password."})
                pwd = self._new_password_flow(sock, buf)
                if pwd is None:
                    return None
                salt = self._generate_salt()
                hashed = self._hash_password(pwd, salt)
                self.passwords[name] = {"salt": salt, "hash": hashed}
                self._save_passwords()
                self._log(f"New account created for '{name}' from {addr}")

            # ── Finalize connection ──
            with self.lock:
                if name in self.clients:
                    self._send(sock, {"type": "error",
                                      "content": f"'{name}' just connected from elsewhere. Try again: "})
                    continue
                color = self._color_for(name)
                self.clients[name] = {"socket": sock, "address": addr,
                                      "room": "general", "color": color}
                self.rooms["general"]["users"].add(name)
            return name

    def _new_password_flow(self, sock, buf) -> str | None:
        """Guide user through password creation. Returns password or None."""
        rules_text = "\n".join(f"  • {r['description']}" for r in self.password_rules)
        self._send(sock, {"type": "system",
                          "content": f"Password rules:\n{rules_text}"})
        while True:
            self._send(sock, {"type": "auth_prompt",
                              "content": "Choose a password: "})
            line = self._read_line(sock, buf)
            if line is None:
                return None
            try:
                pwd = json.loads(line).get("content", "")
            except json.JSONDecodeError:
                continue

            violations = self._check_password_rules(pwd)
            if violations:
                msg = "Password rejected:\n" + "\n".join(f"  ✗ {v}" for v in violations)
                self._send(sock, {"type": "error", "content": msg + "\n"})
                continue

            # Confirmation
            self._send(sock, {"type": "auth_prompt",
                              "content": "Confirm password: "})
            line = self._read_line(sock, buf)
            if line is None:
                return None
            try:
                confirm = json.loads(line).get("content", "")
            except json.JSONDecodeError:
                continue

            if pwd != confirm:
                self._send(sock, {"type": "error",
                                  "content": "Passwords do not match. Try again.\n"})
                continue

            entropy = self._password_entropy(pwd)
            strength = self._strength_label(entropy)
            self._send(sock, {"type": "system",
                              "content": f"Password strength: {strength} ({entropy:.0f} bits)"})
            return pwd

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
