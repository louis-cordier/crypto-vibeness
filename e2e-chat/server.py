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
import tea_cipher

import kem

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
        self.session_keys: dict[str, bytes] = {}
        self.public_keys: dict[str, dict] = {}   # username -> {"n": "0x...", "e": 65537}
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

    # ── KEM handshake (session key exchange) ────────────────────────────

    def _kem_handshake(self, sock, buf, name: str) -> bytes | None:
        """RSA-KEM handshake: receive client pubkey, send encrypted session key."""
        self._send(sock, {"type": "kem_request", "username": name})
        line = self._read_line(sock, buf)
        if line is None:
            return None
        try:
            data = json.loads(line)
            if data.get("type") != "kem_pubkey":
                return None
            public_key = kem.pubkey_from_dict(data)
            # Store public key in directory for E2EE
            self.public_keys[name] = kem.pubkey_to_dict(public_key)
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

        ciphertext, session_key = kem.encapsulate(public_key)
        self._send(sock, {"type": "kem_response",
                          "ciphertext": kem.ct_to_b64(ciphertext)})
        return session_key

    def _get_session_key(self, username: str) -> bytes | None:
        return self.session_keys.get(username)

    def delete_user(self, username: str, notify: bool = True) -> bool:
        """Delete a user account (remove from password file, disconnect if online).

        If notify=True (admin deletion), send a system message to the client.
        If notify=False (self-deletion), the caller already sent a quit message.
        """
        # Step 1: remove from password store (lock held briefly)
        with self.lock:
            existed = username in self.passwords
            if not existed:
                return False
            self.passwords.pop(username, None)
            self._save_passwords()
            self.session_keys.pop(username, None)
            self._log(f"User '{username}' removed from password file")
            sock = self.clients.get(username, {}).get("socket") if username in self.clients else None

        # Step 2: notify and disconnect (lock released to avoid deadlock)
        if sock and notify:
            try:
                self._send(sock, {"type": "system",
                                  "content": "Your account has been deleted by admin. Disconnecting."})
            except OSError:
                pass
        if sock:
            self._disconnect(username)
            self._log(f"User '{username}' disconnected due to deletion")
        return True

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

    # ── E2EE relay (DMs, pubkey directory) ──────────────────────────────

    def _handle_e2ee(self, username: str, raw: dict):
        """Handle E2EE message types: pubkey requests, DM key exchange, DMs."""
        t = raw.get("type")
        sock = self.clients[username]["socket"]

        if t == "get_pubkey":
            target = raw.get("target", "")
            with self.lock:
                pubkey = self.public_keys.get(target)
                online = target in self.clients
            if pubkey and online:
                self._send(sock, {"type": "pubkey_response",
                                  "username": target, **pubkey})
            else:
                self._send(sock, {"type": "error",
                                  "content": f"User '{target}' is not online."})

        elif t == "dm_key_exchange":
            target = raw.get("to", "")
            with self.lock:
                info = self.clients.get(target)
            if info:
                fwd = {k: v for k, v in raw.items() if k != "to"}
                fwd["from"] = username
                self._send(info["socket"], fwd)
                self._log(f"DM key exchange: {username} → {target}")
            else:
                self._send(sock, {"type": "error",
                                  "content": f"User '{target}' is not online."})

        elif t == "dm":
            target = raw.get("to", "")
            with self.lock:
                info = self.clients.get(target)
            if info:
                fwd = {k: v for k, v in raw.items() if k != "to"}
                fwd["from"] = username
                self._send(info["socket"], fwd)
                self._log(f"DM (E2EE): {username} → {target}")
            else:
                self._send(sock, {"type": "error",
                                  "content": f"User '{target}' is not online."})

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

            # ── KEM handshake (both login and register) ──
            session_key = self._kem_handshake(sock, buf, name)
            if session_key is None:
                self._send(sock, {"type": "error",
                                  "content": "Key exchange failed."})
                return None
            self._log(f"KEM handshake completed for '{name}'")

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
                self.session_keys[name] = session_key
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
                    raw = json.loads(line)
                    raw_type = raw.get("type")
                    content = raw.get("content", "")
                    encrypted = raw.get("encrypted", False)
                    signature = raw.get("signature")
                except json.JSONDecodeError:
                    continue
                # E2EE messages: relay as opaque blobs
                if raw_type in ("get_pubkey", "dm_key_exchange", "dm"):
                    self._handle_e2ee(username, raw)
                    continue
                # Decrypt if encrypted
                if encrypted:
                    sender_key = self._get_session_key(username)
                    if sender_key:
                        try:
                            content = tea_cipher.decrypt_b64(content, sender_key)
                        except Exception:
                            self._send(sock, {"type": "error",
                                              "content": "Decryption failed."})
                            continue
                self._process(username, content, buf, signature=signature)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            if username:
                self._disconnect(username)

    # ── message processing ───────────────────────────────────────────

    def _process(self, username: str, content: str, buf: list[str],
                 *, signature: str | None = None):
        if content.startswith("/"):
            self._command(username, content, buf)
        else:
            with self.lock:
                info = self.clients.get(username)
            if not info:
                return
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            base_msg = {
                "type": "message", "username": username,
                "content": content, "timestamp": ts, "color": info["color"],
            }
            if signature:
                base_msg["signature"] = signature
            self._broadcast_encrypted(info["room"], base_msg)
            self._log(f"[{info['room']}] {username}: {content}")

    def _broadcast_encrypted(self, room: str, data: dict,
                             *, exclude: str | None = None):
        """Broadcast a message, encrypting the content for each recipient."""
        with self.lock:
            users = list(self.rooms.get(room, {}).get("users", []))
        plaintext = data.get("content", "")
        sender = data.get("username", "")
        sender_pubkey = self.public_keys.get(sender)
        for u in users:
            if u == exclude:
                continue
            with self.lock:
                info = self.clients.get(u)
            if not info:
                continue
            recipient_key = self._get_session_key(u)
            if recipient_key:
                msg = dict(data)
                msg["content"] = tea_cipher.encrypt_b64(plaintext, recipient_key)
                msg["encrypted"] = True
                if sender_pubkey:
                    msg["sender_pubkey"] = sender_pubkey
                self._send(info["socket"], msg)
            else:
                self._send(info["socket"], data)

    def _command(self, username: str, text: str, buf: list[str]):
        parts = text.split()
        cmd = parts[0].lower()
        sock = self.clients[username]["socket"]

        if cmd == "/help":
            self._send(sock, {"type": "system", "content":
                "Commands:\n"
                "  /rooms                       – List all rooms\n"
                "  /create <name> [password]     – Create a room\n"
                "  /delete <name>                – Delete a room you created\n"
                "  /join <name> [password]       – Join a room\n"
                "  /leave                        – Back to general\n"
                "  /who                          – Users in current room\n"
                "  /dm <user> <message>          – Encrypted direct message\n"
                "  /quit                         – Disconnect\n"
                "  /deleteaccount                – Delete your account"})

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

        elif cmd == "/delete":
            if len(parts) < 2:
                self._send(sock, {"type": "error",
                                  "content": "Usage: /delete <name>"})
                return
            name = parts[1]
            if name == "general":
                self._send(sock, {"type": "error",
                                  "content": "Cannot delete room 'general'."})
                return
            with self.lock:
                if name not in self.rooms:
                    self._send(sock, {"type": "error",
                                      "content": f"Room '{name}' does not exist."})
                    return
                displaced = list(self.rooms[name]["users"])
                for u in displaced:
                    self.clients[u]["room"] = "general"
                    self.rooms["general"]["users"].add(u)
                del self.rooms[name]
            for u in displaced:
                if u != username:
                    self._send(self.clients[u]["socket"], {"type": "system",
                        "content": f"Room '{name}' has been deleted by {username}. "
                                   f"You are back in 'general'."})
            self._send(sock, {"type": "system",
                              "content": f"Room '{name}' deleted."})
            self._log(f"{username} deleted room '{name}' ({len(displaced)} users moved)")

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

        elif cmd == "/deleteaccount":
            self._send(sock, {"type": "auth_prompt",
                              "content": "Confirm your password to delete your account: "})
            line = self._read_line(sock, buf)
            try:
                pwd = json.loads(line).get("content", "") if line else ""
            except json.JSONDecodeError:
                pwd = ""
            if not self._verify_password(username, pwd):
                self._send(sock, {"type": "error",
                                  "content": "Wrong password. Account not deleted."})
                self._log(f"{username} failed to delete account (wrong password)")
                return
            self._send(sock, {"type": "quit",
                              "content": "Your account has been deleted. Goodbye!"})
            self.delete_user(username, notify=False)
            self._log(f"{username} deleted their own account")

        else:
            self._send(sock, {"type": "error",
                              "content": f"Unknown command: {cmd}. Type /help."})

    # ── disconnect ───────────────────────────────────────────────────

    def _disconnect(self, username: str):
        with self.lock:
            info = self.clients.pop(username, None)
            self.session_keys.pop(username, None)
            self.public_keys.pop(username, None)
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


def delete_user_file(username: str) -> bool:
    """Delete a user from the password file without running the server.

    Returns True if a user was removed, False if not found.
    """
    if not os.path.exists(PASSWORD_FILE):
        return False
    changed = False
    lines = []
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.rstrip("\n").split(":", 2)
            if parts[0] == username:
                changed = True
                continue
            lines.append(line)
    if changed:
        with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
            f.writelines(lines)
    return changed


if __name__ == "__main__":
    # CLI: support deleting a user: python server.py --delete-user username
    if len(sys.argv) >= 3 and sys.argv[1] in ("--delete-user", "-d"):
        user = sys.argv[2]
        ok = delete_user_file(user)
        if ok:
            print(f"User '{user}' deleted from {PASSWORD_FILE}.")
            sys.exit(0)
        else:
            print(f"User '{user}' not found in {PASSWORD_FILE}.")
            sys.exit(1)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    ChatServer(port).start()
