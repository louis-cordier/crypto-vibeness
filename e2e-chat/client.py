#!/usr/bin/env python3
"""Multi-user chat client with password authentication."""

import socket
import threading
import json
import sys
import getpass
import queue
import os
import base64
import datetime
import tea_cipher
import kem

DEFAULT_PORT = 5555
RESET = "\033[0m"


# ── server discovery ─────────────────────────────────────────────────

def _get_local_ip() -> str:
    """Return the local IP address used for LAN communication."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def _probe_server(ip: str, port: int, results: list, lock: threading.Lock):
    """Try to connect to ip:port and check for a chat server prompt."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        s.connect((ip, port))
        data = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()
        if '"prompt"' in data or '"type"' in data:
            with lock:
                results.append(ip)
    except (OSError, ConnectionRefusedError, TimeoutError):
        pass


def discover_servers(port: int) -> list[str]:
    """Scan the local /24 subnet for chat servers on the given port."""
    local_ip = _get_local_ip()
    prefix = ".".join(local_ip.split(".")[:3]) + "."

    print(f"\033[93m🔍 Scanning network {prefix}0/24 on port {port}...\033[0m")

    results: list[str] = []
    lock = threading.Lock()
    threads: list[threading.Thread] = []

    # Also probe localhost
    for i in list(range(1, 255)) + [0]:
        ip = "127.0.0.1" if i == 0 else prefix + str(i)
        t = threading.Thread(target=_probe_server, args=(ip, port, results, lock))
        t.start()
        threads.append(t)
        # Limit concurrency to avoid socket exhaustion
        if len(threads) >= 50:
            for tt in threads:
                tt.join()
            threads.clear()

    for t in threads:
        t.join()

    return results


def select_server(port: int) -> str:
    """Discover servers and let the user pick one, or enter an IP manually."""
    servers = discover_servers(port)

    if not servers:
        print("\033[91m❌ No servers found on the network.\033[0m")
        manual = input("Enter server IP manually (or 'q' to quit): ").strip()
        if manual.lower() == "q":
            sys.exit(0)
        return manual

    print(f"\033[92m✅ Found {len(servers)} server(s):\033[0m")
    for i, ip in enumerate(servers, 1):
        label = " (localhost)" if ip == "127.0.0.1" else ""
        print(f"  {i}. {ip}{label}")
    print(f"  {len(servers) + 1}. Enter IP manually")

    while True:
        choice = input(f"Select server [1-{len(servers) + 1}]: ").strip()
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(servers):
                return servers[n - 1]
            if n == len(servers) + 1:
                return input("Enter server IP: ").strip()
        print("Invalid choice.")


class ChatClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.username: str | None = None
        self.authenticated = threading.Event()
        self._buf = ""
        self._msg_queue: list[dict] = []
        self._msg_lock = threading.Lock()
        self._msg_ready = threading.Event()
        self._mid_auth_queue: queue.Queue[dict] = queue.Queue()
        self._encryption_key: bytes | None = None
        self._rsa_pub: tuple[int, int] | None = None
        self._rsa_priv: tuple[int, int] | None = None
        # E2EE state for DMs
        self._peer_keys: dict[str, bytes] = {}       # peer -> session key
        self._peer_pubkeys: dict[str, tuple] = {}    # peer -> RSA pubkey
        self._pubkey_response: dict | None = None
        self._pubkey_event = threading.Event()

    # ── network ──────────────────────────────────────────────────────

    def _send_raw(self, data: dict):
        """Send a JSON message without encryption (for KEM handshake)."""
        raw = json.dumps(data) + "\n"
        self.sock.sendall(raw.encode("utf-8"))

    def _send(self, content: str):
        if self._encryption_key and not content.startswith("/"):
            # Sign the plaintext
            sig = kem.rsa_sign(content.encode("utf-8"), self._rsa_priv)
            sig_b64 = base64.b64encode(sig).decode()
            encrypted = tea_cipher.encrypt_b64(content, self._encryption_key)
            msg = json.dumps({"content": encrypted, "encrypted": True,
                              "signature": sig_b64}) + "\n"
        else:
            msg = json.dumps({"content": content}) + "\n"
        self.sock.sendall(msg.encode("utf-8"))

    def _recv_loop(self):
        """Receive messages: queue during auth, display after."""
        try:
            while self.running:
                chunk = self.sock.recv(4096)
                if not chunk:
                    if self.running:
                        print("\n\033[91mDisconnected from server.\033[0m")
                    self.running = False
                    self._msg_ready.set()
                    break
                self._buf += chunk.decode("utf-8")
                while "\n" in self._buf:
                    line, self._buf = self._buf.split("\n", 1)
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if self.authenticated.is_set():
                        self._display(msg)
                    else:
                        with self._msg_lock:
                            self._msg_queue.append(msg)
                            self._msg_ready.set()
        except (ConnectionResetError, OSError):
            if self.running:
                print("\n\033[91mConnection lost.\033[0m")
            self.running = False
            self._msg_ready.set()

    def _wait_msg(self) -> dict | None:
        """Wait for the next message during auth phase."""
        while self.running:
            self._msg_ready.wait(timeout=0.5)
            with self._msg_lock:
                if self._msg_queue:
                    msg = self._msg_queue.pop(0)
                    if not self._msg_queue:
                        self._msg_ready.clear()
                    return msg
        return None

    def _drain_messages(self) -> list[dict]:
        """Get all pending messages."""
        with self._msg_lock:
            msgs = list(self._msg_queue)
            self._msg_queue.clear()
            self._msg_ready.clear()
        return msgs

    # ── display ──────────────────────────────────────────────────────

    def _display(self, msg: dict):
        t = msg.get("type")

        if t == "prompt":
            print(msg["content"], end="", flush=True)

        elif t == "auth_prompt":
            self._mid_auth_queue.put(msg)

        elif t == "error":
            print(f"\n\033[91m✗ {msg['content']}\033[0m", flush=True)

        elif t == "welcome":
            self.username = msg.get("username")
            print(f"\n\033[92m{msg['content']}\033[0m")

        elif t == "message":
            color = msg.get("color", "")
            ts = msg.get("timestamp", "")
            user = msg.get("username", "")
            body = msg.get("content", "")
            if msg.get("encrypted") and self._encryption_key:
                try:
                    body = tea_cipher.decrypt_b64(body, self._encryption_key)
                except Exception:
                    body = "[decryption failed]"
            # Verify signature if present
            sig_b64 = msg.get("signature")
            sender_pk = msg.get("sender_pubkey")
            if sig_b64 and sender_pk:
                try:
                    sig = base64.b64decode(sig_b64)
                    pubkey = kem.pubkey_from_dict(sender_pk)
                    if not kem.rsa_verify(body.encode("utf-8"), sig, pubkey):
                        print(f"\r\033[91m⚠️  SECURITY ALERT: Message from "
                              f"{user} has INVALID signature!\033[0m")
                        return
                except Exception:
                    print(f"\r\033[91m⚠️  SECURITY ALERT: Could not verify "
                          f"signature from {user}!\033[0m")
                    return
            print(f"\r[{ts}] {color}{user}{RESET}: {body}")

        elif t == "system":
            print(f"\r\033[93m⚡ {msg['content']}\033[0m")

        elif t == "room_list":
            rooms = msg.get("rooms", [])
            print("\r\033[96m╔══ Available Rooms ══╗\033[0m")
            for r in rooms:
                name, count = r["name"], r["count"]
                if r["protected"]:
                    print(f"\033[96m║\033[0m \033[93m🔒 {name}\033[0m ({count} users)")
                else:
                    print(f"\033[96m║\033[0m   {name} ({count} users)")
            print("\033[96m╚═════════════════════╝\033[0m")

        elif t == "quit":
            print(f"\033[93m{msg['content']}\033[0m")
            self.running = False

        # ── E2EE DM types ──
        elif t == "pubkey_response":
            self._pubkey_response = msg
            self._pubkey_event.set()

        elif t == "dm_key_exchange":
            sender = msg.get("from", "")
            try:
                encrypted_key = base64.b64decode(msg["encrypted_key"])
                session_key = kem.rsa_decrypt(encrypted_key, self._rsa_priv)
                self._peer_keys[sender] = session_key
                sender_pk = msg.get("sender_pubkey")
                if sender_pk:
                    self._peer_pubkeys[sender] = kem.pubkey_from_dict(sender_pk)
                print(f"\r\033[93m🔑 Secure DM channel established "
                      f"with {sender}.\033[0m")
            except Exception:
                print(f"\r\033[91m✗ Failed to establish DM channel "
                      f"with {sender}.\033[0m")

        elif t == "dm":
            self._display_dm(msg)

    def _display_dm(self, msg: dict):
        """Handle an incoming E2EE direct message."""
        sender = msg.get("from", "")
        content = msg.get("content", "")
        sig_b64 = msg.get("signature", "")

        # Verify signature
        peer_pubkey = self._peer_pubkeys.get(sender)
        if sig_b64 and peer_pubkey:
            try:
                sig = base64.b64decode(sig_b64)
                if not kem.rsa_verify(content.encode("utf-8"), sig, peer_pubkey):
                    print(f"\r\033[91m⚠️  SECURITY ALERT: DM from {sender} "
                          f"has INVALID signature! Message may have been "
                          f"tampered with.\033[0m")
                    return
            except Exception:
                print(f"\r\033[91m⚠️  SECURITY ALERT: Could not verify "
                      f"DM signature from {sender}!\033[0m")
                return
        elif sig_b64 and not peer_pubkey:
            print(f"\r\033[91m⚠️  SECURITY ALERT: Cannot verify DM from "
                  f"{sender} — no public key available.\033[0m")

        # Decrypt
        peer_key = self._peer_keys.get(sender)
        if peer_key:
            try:
                plaintext = tea_cipher.decrypt_b64(content, peer_key)
            except Exception:
                print(f"\r\033[91m⚠️  SECURITY ALERT: Could not decrypt "
                      f"DM from {sender}.\033[0m")
                return
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\r[{ts}] \033[35m[DM ← {sender}]\033[0m: {plaintext}")
        else:
            print(f"\r\033[91m✗ DM from {sender}: no session key "
                  f"available.\033[0m")

    # ── DM handling ──────────────────────────────────────────────────

    def _establish_dm_key(self, target: str) -> bool:
        """Request peer's pubkey and establish a DM session key."""
        self._pubkey_response = None
        self._pubkey_event.clear()
        self._send_raw({"type": "get_pubkey", "target": target})
        self._pubkey_event.wait(timeout=5)

        if self._pubkey_response is None:
            return False

        try:
            peer_pubkey = kem.pubkey_from_dict(self._pubkey_response)
            self._peer_pubkeys[target] = peer_pubkey
        except (KeyError, ValueError):
            return False

        session_key = os.urandom(16)
        ct = kem.rsa_encrypt(session_key, peer_pubkey)
        self._send_raw({
            "type": "dm_key_exchange",
            "to": target,
            "encrypted_key": base64.b64encode(ct).decode(),
            "sender_pubkey": kem.pubkey_to_dict(self._rsa_pub),
        })
        self._peer_keys[target] = session_key
        print(f"\033[93m🔑 Secure DM channel established with "
              f"{target}.\033[0m")
        return True

    def _handle_dm(self, text: str):
        """Process /dm <user> <message>."""
        parts = text.split(None, 2)
        if len(parts) < 3:
            print("\033[91m✗ Usage: /dm <username> <message>\033[0m")
            return
        target = parts[1]
        message = parts[2]

        if target == self.username:
            print("\033[91m✗ Cannot DM yourself.\033[0m")
            return

        # Establish session key if needed
        if target not in self._peer_keys:
            if not self._establish_dm_key(target):
                print(f"\033[91m✗ Could not establish secure channel "
                      f"with {target}.\033[0m")
                return

        # Encrypt with peer session key
        encrypted = tea_cipher.encrypt_b64(message, self._peer_keys[target])
        # Sign the ciphertext
        sig = kem.rsa_sign(encrypted.encode("utf-8"), self._rsa_priv)
        sig_b64 = base64.b64encode(sig).decode()

        self._send_raw({
            "type": "dm",
            "to": target,
            "content": encrypted,
            "signature": sig_b64,
        })
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] \033[35m[DM → {target}]\033[0m: {message}")

    # ── RSA key management ──────────────────────────────────────────────

    def _key_dir(self) -> str:
        return os.path.join(".", "users", self.username or "_unknown")

    def _load_or_generate_keypair(self):
        """Load or generate RSA keypair for this user."""
        d = self._key_dir()
        os.makedirs(d, exist_ok=True)
        priv_path = os.path.join(d, f"{self.username}.priv")
        pub_path = os.path.join(d, f"{self.username}.pub")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            self._rsa_priv = kem.load_private_key(priv_path)
            self._rsa_pub = kem.load_public_key(pub_path)
            print("\033[93m🔑 RSA keypair loaded.\033[0m")
        else:
            print("\033[93m🔑 Generating RSA keypair…\033[0m", flush=True)
            self._rsa_pub, self._rsa_priv = kem.generate_keypair()
            kem.save_private_key(self._rsa_priv, priv_path)
            kem.save_public_key(self._rsa_pub, pub_path)
            print("\033[93m🔑 RSA keypair saved.\033[0m")

    # ── authentication phase ─────────────────────────────────────────

    def _auth_phase(self) -> bool:
        """Handle login/register before entering the chat loop."""
        while self.running:
            msg = self._wait_msg()
            if msg is None:
                return False
            t = msg.get("type")

            if t == "prompt":
                print(msg["content"], end="", flush=True)
                text = input()
                self._send(text)

            elif t == "auth_prompt":
                pwd = getpass.getpass(msg["content"])
                self._send(pwd)

            elif t == "error":
                print(f"\033[91m✗ {msg['content']}\033[0m", flush=True)

            elif t == "kem_request":
                self.username = msg.get("username")
                self._load_or_generate_keypair()
                pub_dict = kem.pubkey_to_dict(self._rsa_pub)
                pub_dict["type"] = "kem_pubkey"
                self._send_raw(pub_dict)

            elif t == "kem_response":
                ct = kem.ct_from_b64(msg["ciphertext"])
                self._encryption_key = kem.decapsulate(ct, self._rsa_priv)
                print("\033[93m🔐 Session key established via KEM.\033[0m")

            elif t == "system":
                print(f"\033[93m⚡ {msg['content']}\033[0m")

            elif t == "welcome":
                self.username = msg.get("username")
                print(f"\n\033[92m{msg['content']}\033[0m")
                return True

        return False

    # ── main ─────────────────────────────────────────────────────────

    def start(self):
        try:
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print("\033[91mCould not connect to server.\033[0m")
            return

        threading.Thread(target=self._recv_loop, daemon=True).start()

        # Phase 1: authentication (sequential input)
        if not self._auth_phase():
            self.running = False
            self.sock.close()
            print("Disconnected.")
            return

        if self._encryption_key:
            print("\033[93m🔐 Encryption active (RSA-KEM + TEA-CBC 128-bit)\033[0m")

        # Phase 2: chat loop
        self.authenticated.set()
        for msg in self._drain_messages():
            self._display(msg)

        try:
            while self.running:
                text = input()
                if not self.running:
                    break
                # Erase the typed line so only the server echo is shown
                print("\033[A\033[2K", end="", flush=True)
                if text.strip().lower().startswith("/dm "):
                    self._handle_dm(text.strip())
                elif text.strip().lower() == "/quit":
                    self._send(text)
                    self.running = False
                    break
                else:
                    self._send(text)
                # If server replies with an auth_prompt (e.g. /deleteaccount),
                # handle it here in the main thread with hidden input
                try:
                    prompt_msg = self._mid_auth_queue.get(timeout=0.8)
                    pwd = getpass.getpass(prompt_msg["content"])
                    self._send(pwd)
                except queue.Empty:
                    pass
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self.running = False
            try:
                self.sock.close()
            except OSError:
                pass
            print("Disconnected.")


if __name__ == "__main__":
    port = DEFAULT_PORT
    host = None

    if len(sys.argv) > 1:
        # First arg could be host or port
        if sys.argv[1].replace(".", "").isdigit() and "." in sys.argv[1]:
            host = sys.argv[1]
            if len(sys.argv) > 2:
                port = int(sys.argv[2])
        else:
            port = int(sys.argv[1])
            if len(sys.argv) > 2:
                host = sys.argv[2]

    if host is None:
        host = select_server(port)

    ChatClient(host, port).start()
