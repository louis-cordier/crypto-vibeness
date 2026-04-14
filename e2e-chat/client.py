#!/usr/bin/env python3
"""Multi-user chat client with password authentication."""

import socket
import threading
import json
import sys
import getpass
import queue

DEFAULT_PORT = 5555
RESET = "\033[0m"


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

    # ── network ──────────────────────────────────────────────────────

    def _send(self, content: str):
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
            # In chat mode, route to the main thread for masked input
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
                self._send(text)
                if text.strip().lower() == "/quit":
                    self.running = False
                    break
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
    host = "localhost"
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]
    ChatClient(host, port).start()
