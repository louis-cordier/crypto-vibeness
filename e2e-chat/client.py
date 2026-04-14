#!/usr/bin/env python3
"""Multi-user chat client (IRC-like, no auth, no encryption)."""

import socket
import threading
import json
import sys

DEFAULT_PORT = 5555
RESET = "\033[0m"


class ChatClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.username: str | None = None

    # ── network ──────────────────────────────────────────────────────

    def _send(self, content: str):
        msg = json.dumps({"content": content}) + "\n"
        self.sock.sendall(msg.encode("utf-8"))

    def _recv_loop(self):
        buf = ""
        try:
            while self.running:
                chunk = self.sock.recv(4096)
                if not chunk:
                    if self.running:
                        print("\n\033[91mDisconnected from server.\033[0m")
                    self.running = False
                    break
                buf += chunk.decode("utf-8")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    try:
                        self._handle(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except (ConnectionResetError, OSError):
            if self.running:
                print("\n\033[91mConnection lost.\033[0m")
            self.running = False

    # ── display ──────────────────────────────────────────────────────

    def _handle(self, msg: dict):
        t = msg.get("type")

        if t == "prompt":
            print(msg["content"], end="", flush=True)

        elif t == "error":
            print(f"\033[91m✗ {msg['content']}\033[0m", end="", flush=True)

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

    # ── main ─────────────────────────────────────────────────────────

    def start(self):
        try:
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print("\033[91mCould not connect to server.\033[0m")
            return

        threading.Thread(target=self._recv_loop, daemon=True).start()

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
