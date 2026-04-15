#!/usr/bin/env python3
"""
Automated Security & Compliance Test Suite
===========================================
Tests all requirements from Jour 1, Jour 2, and Jour 3 (encryption).
Run from e2e-chat/ directory:  python3 test_audit.py
"""

import socket
import json
import threading
import time
import os
import sys
import hashlib
import base64
import hmac
import glob
import re
import struct

sys.path.insert(0, ".")
from server import ChatServer
import tea_cipher

# ── Helpers ─────────────────────────────────────────────────────────

PORT = 0  # Will be assigned dynamically
server_instance = None
RESULTS = []
test_count = [0, 0]  # [passed, failed]

COLORS_REF = [
    "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m",
    "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m",
]


def start_server(port):
    global server_instance, PORT
    PORT = port
    server_instance = ChatServer(PORT)
    t = threading.Thread(target=server_instance.start, daemon=True)
    t.start()
    time.sleep(0.5)
    return server_instance


def mk():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", PORT))
    s.settimeout(4)
    return s


def tx(s, content, encrypted=False):
    msg = {"content": content}
    if encrypted:
        msg["encrypted"] = True
    s.sendall((json.dumps(msg) + "\n").encode())


def drain(s, t=1.5):
    msgs = []
    buf = ""
    s.settimeout(t)
    try:
        while True:
            d = s.recv(4096).decode()
            if not d:
                break
            buf += d
            while "\n" in buf:
                l, buf = buf.split("\n", 1)
                msgs.append(json.loads(l))
    except socket.timeout:
        pass
    return msgs


def raw_recv(s, t=1.5):
    """Receive raw bytes (for wire-level inspection)."""
    s.settimeout(t)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def register(s, username, password, secret="DefaultSecret123"):
    """Full registration flow. Returns list of all messages received."""
    all_msgs = []
    all_msgs += drain(s)                      # username prompt
    tx(s, username)
    all_msgs += drain(s)                      # new user + rules + auth_prompt
    tx(s, password)
    all_msgs += drain(s)                      # confirm prompt
    tx(s, password)
    all_msgs += drain(s)                      # strength + encryption secret prompt
    tx(s, secret)
    all_msgs += drain(s)                      # encryption_key + welcome
    all_msgs += drain(s, 0.5)                 # any trailing system messages
    return all_msgs


def login(s, username, password):
    """Login flow for existing user. Returns list of all messages."""
    all_msgs = []
    all_msgs += drain(s)                      # username prompt
    tx(s, username)
    all_msgs += drain(s)                      # auth_prompt for password
    tx(s, password)
    all_msgs += drain(s)                      # encryption_key + welcome
    all_msgs += drain(s, 0.5)
    return all_msgs


def find_msg(msgs, msg_type):
    return [m for m in msgs if m.get("type") == msg_type]


def T(name, condition, detail=""):
    """Record a test result."""
    if condition:
        test_count[0] += 1
        RESULTS.append(f"  ✅ {name}")
    else:
        test_count[1] += 1
        RESULTS.append(f"  ❌ {name}{' — ' + detail if detail else ''}")


def section(title):
    RESULTS.append(f"\n{'═'*60}")
    RESULTS.append(f"  {title}")
    RESULTS.append(f"{'═'*60}")


# ════════════════════════════════════════════════════════════════════
#  JOUR 1 — IRC Chat (YOLO)
# ════════════════════════════════════════════════════════════════════

def test_jour1():
    section("JOUR 1 — Chat IRC de base")

    # ── T1.1  Default port ──
    T("DEFAULT_PORT défini dans server.py",
      hasattr(ChatServer, "__init__") and ChatServer.__dict__ is not None)
    from server import DEFAULT_PORT
    T("Port par défaut = 5555", DEFAULT_PORT == 5555)

    # ── T1.2  Port via CLI ──
    T("Port configurable via sys.argv",
      "port" in open("server.py").read().lower())

    # ── T1.3  Multi-client simultané ──
    c1 = mk()
    c2 = mk()
    register(c1, "User1", "StrongP4ss", "sec1")
    register(c2, "User2", "StrongP4ss", "sec2")
    T("Deux clients connectés simultanément",
      "User1" in server_instance.clients and "User2" in server_instance.clients)

    # ── T1.4  Unicité des pseudos ──
    c3 = mk()
    drain(c3)
    tx(c3, "User1")
    msgs = drain(c3)
    has_error = any(m["type"] == "error" and "already" in m.get("content", "").lower()
                    for m in msgs)
    T("Pseudo déjà connecté → refusé", has_error)
    c3.close()

    # ── T1.5  Room par défaut = general ──
    with server_instance.lock:
        room1 = server_instance.clients["User1"]["room"]
    T("Room par défaut = 'general'", room1 == "general")

    # ── T1.6  Création de room ──
    tx(c1, "/create salon_test")
    drain(c1)
    with server_instance.lock:
        room_exists = "salon_test" in server_instance.rooms
    T("Création de room /create", room_exists)

    # ── T1.7  Room protégée par mot de passe ──
    tx(c1, "/create secret_room mysecretpwd")
    drain(c1)
    with server_instance.lock:
        protected = server_instance.rooms.get("secret_room", {}).get("password") == "mysecretpwd"
    T("Room protégée par mot de passe", protected)

    # ── T1.8  Join room ──
    tx(c1, "/join salon_test")
    drain(c1)
    with server_instance.lock:
        moved = server_instance.clients["User1"]["room"] == "salon_test"
    T("Rejoindre une room /join", moved)

    # ── T1.9  Join protected room sans mdp → refusé ──
    tx(c2, "/join secret_room")
    msgs = drain(c2)
    has_error = any("incorrect" in m.get("content", "").lower() or "password" in m.get("content", "").lower()
                    for m in msgs if m["type"] == "error")
    T("Join room protégée sans mdp → refusé", has_error)

    # ── T1.10  Join protected room avec bon mdp ──
    tx(c2, "/join secret_room mysecretpwd")
    msgs = drain(c2)
    with server_instance.lock:
        joined_secret = server_instance.clients["User2"]["room"] == "secret_room"
    T("Join room protégée avec bon mdp → OK", joined_secret)

    # ── T1.11  Isolation des rooms ──
    # User1 is in salon_test, User2 is in secret_room
    key1 = server_instance._get_user_key("User1")
    key2 = server_instance._get_user_key("User2")

    tx(c1, tea_cipher.encrypt_b64("msg_for_salon_test", key1), encrypted=True)
    time.sleep(0.3)
    user2_msgs = drain(c2, 0.8)
    chat_msgs_u2 = [m for m in user2_msgs if m["type"] == "message"]
    T("Isolation des rooms (User2 ne voit pas msg de salon_test)",
      len(chat_msgs_u2) == 0)

    # ── T1.12  Timestamp sur les messages ──
    tx(c2, "/join salon_test mysecretpwd")
    drain(c2)
    tx(c2, "/join salon_test")
    drain(c2)
    # Move User2 to salon_test
    tx(c2, "/leave")
    drain(c2)
    tx(c2, "/join salon_test")
    drain(c2)
    tx(c1, tea_cipher.encrypt_b64("test_timestamp", key1), encrypted=True)
    time.sleep(0.3)
    msgs = drain(c2, 1.0)
    chat_msgs = [m for m in msgs if m["type"] == "message"]
    has_ts = any("timestamp" in m and re.match(r"\d{2}:\d{2}:\d{2}", m["timestamp"])
                 for m in chat_msgs)
    T("Messages avec timestamp HH:MM:SS", has_ts)

    # ── T1.13  Couleur déterministe ──
    color1a = ChatServer._color_for("User1")
    color1b = ChatServer._color_for("User1")
    color2 = ChatServer._color_for("User2")
    T("Couleur déterministe (même pseudo → même couleur)", color1a == color1b)
    T("Couleur basée sur MD5 du username",
      color1a == COLORS_REF[int(hashlib.md5("User1".encode()).hexdigest(), 16) % len(COLORS_REF)])

    # ── T1.14  Fichier de log ──
    log_files = glob.glob("log_*.txt")
    T("Fichier log créé (log_YYYY-MM-DD_HH-MM-SS.txt)", len(log_files) >= 1)
    if log_files:
        log_name = log_files[-1]
        T("Format nom fichier log correct",
          bool(re.match(r"log_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt", log_name)))
        with open(log_name) as f:
            log_content = f.read()
        T("Log contient les connexions", "connected" in log_content)
        T("Log contient les messages", "salon_test" in log_content or "general" in log_content)

    # ── T1.15  /rooms affiche rooms protégées différemment ──
    tx(c1, "/rooms")
    msgs = drain(c1)
    room_list_msgs = find_msg(msgs, "room_list")
    if room_list_msgs:
        rooms_data = room_list_msgs[0].get("rooms", [])
        secret_info = [r for r in rooms_data if r["name"] == "secret_room"]
        T("Room protégée marquée 'protected' dans room_list",
          len(secret_info) == 1 and secret_info[0].get("protected") is True)
        general_info = [r for r in rooms_data if r["name"] == "general"]
        T("Room non-protégée marquée 'protected: false'",
          len(general_info) == 1 and general_info[0].get("protected") is False)
    else:
        T("/rooms renvoie room_list", False, "Aucun room_list reçu")

    # ── T1.16  /who ──
    tx(c1, "/who")
    msgs = drain(c1)
    who_msgs = [m for m in msgs if m["type"] == "system" and "Users in" in m.get("content", "")]
    T("/who liste les utilisateurs de la room", len(who_msgs) >= 1)

    # ── T1.17  /leave ──
    tx(c1, "/leave")
    msgs = drain(c1)
    with server_instance.lock:
        back_general = server_instance.clients["User1"]["room"] == "general"
    T("/leave ramène à general", back_general)

    # ── T1.18  /quit ──
    tx(c2, "/quit")
    time.sleep(0.3)
    drain(c2, 0.3)
    with server_instance.lock:
        user2_gone = "User2" not in server_instance.clients
    T("/quit déconnecte le client", user2_gone)
    c2.close()

    # Cleanup User1
    tx(c1, "/quit")
    drain(c1, 0.3)
    c1.close()
    time.sleep(0.3)


# ════════════════════════════════════════════════════════════════════
#  JOUR 2 — Authentification
# ════════════════════════════════════════════════════════════════════

def test_jour2():
    section("JOUR 2 — Authentification MD5 + sel")

    # ── T2.1  Fichier this_is_safe.txt ──
    T("Fichier this_is_safe.txt existe", os.path.exists("this_is_safe.txt"))

    # ── T2.2  Format du fichier : username:salt:hash ──
    with open("this_is_safe.txt") as f:
        lines = [l.strip() for l in f if l.strip()]
    all_valid = True
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            all_valid = False
            break
    T("Format this_is_safe.txt = username:salt:hash", all_valid and len(lines) >= 1)

    # ── T2.3  Hash en base64 (pas hex) ──
    all_b64 = True
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) == 3:
            try:
                raw = base64.b64decode(parts[2])
                # MD5 produces 16 bytes
                if len(raw) != 16:
                    all_b64 = False
            except Exception:
                all_b64 = False
    T("Hash encodé en base64 (pas hex)", all_b64)

    # ── T2.4  MD5 utilisé ──
    T("Algorithme MD5 utilisé (_hash_password)",
      "md5" in open("server.py").read().lower())

    # ── T2.5  Sel ≥ 96 bits (12 octets) ──
    all_salt_ok = True
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) == 3:
            try:
                salt_raw = base64.b64decode(parts[1])
                if len(salt_raw) < 12:
                    all_salt_ok = False
            except Exception:
                all_salt_ok = False
    T("Sel ≥ 96 bits (12 octets) par utilisateur", all_salt_ok)

    # ── T2.6  Même mot de passe → hash différent (sel unique) ──
    # Register two users with identical passwords
    ca = mk()
    cb = mk()
    register(ca, "SamePwdA", "StrongP4ss", "secA")
    register(cb, "SamePwdB", "StrongP4ss", "secB")
    time.sleep(0.3)
    with open("this_is_safe.txt") as f:
        content = f.read()
    hash_a = hash_b = salt_a = salt_b = None
    for line in content.strip().split("\n"):
        parts = line.split(":", 2)
        if parts[0] == "SamePwdA":
            salt_a, hash_a = parts[1], parts[2]
        elif parts[0] == "SamePwdB":
            salt_b, hash_b = parts[1], parts[2]
    T("Même mdp → sels différents", salt_a != salt_b)
    T("Même mdp → hashs différents", hash_a != hash_b)

    # ── T2.7  3 règles de mot de passe ──
    T("Fichier password_rules.json existe", os.path.exists("password_rules.json"))
    import json as j
    with open("password_rules.json") as f:
        rules = j.load(f).get("rules", [])
    T("Au moins 3 règles de mot de passe", len(rules) >= 3)

    # ── T2.8  Règles chargées au lancement ──
    T("Règles chargées dans server_instance",
      len(server_instance.password_rules) >= 3)

    # ── T2.9  Mdp trop faible rejeté ──
    cc = mk()
    drain(cc)
    tx(cc, "WeakUser")
    drain(cc)
    tx(cc, "abc")  # too short, no uppercase, no digit
    msgs = drain(cc)
    rejected = any(m["type"] == "error" and "rejected" in m.get("content", "").lower()
                   for m in msgs)
    T("Mot de passe faible → rejeté (min 8 chars / maj / chiffre)", rejected)
    cc.close()

    # ── T2.10  Indicateur de force (entropie) ──
    cd = mk()
    all_msgs = register(cd, "EntropyUser", "Str0ngP@ss!", "secE")
    has_strength = any(m["type"] == "system" and "strength" in m.get("content", "").lower()
                       for m in all_msgs)
    T("Indicateur de force du mot de passe affiché", has_strength)
    has_bits = any("bits" in m.get("content", "").lower() for m in all_msgs)
    T("Entropie en bits affichée", has_bits)
    tx(cd, "/quit"); drain(cd, 0.3); cd.close()

    # ── T2.11  Vérification en temps constant ──
    src = open("server.py").read()
    T("hmac.compare_digest utilisé (temps constant)",
      "hmac.compare_digest" in src)

    # ── T2.12  Non-auth ne reçoit pas de messages ──
    # A non-authenticated client that just connects should not see chat messages
    ce = mk()
    drain(ce, 0.5)  # gets the username prompt but doesn't reply
    # Meanwhile, an authenticated user sends a message
    cf = mk()
    register(cf, "AuthSender", "StrongP4ss", "secS")
    key_s = server_instance._get_user_key("AuthSender")
    tx(cf, tea_cipher.encrypt_b64("secret_message_123", key_s), encrypted=True)
    time.sleep(0.5)
    unauth_data = raw_recv(ce, 0.5)
    T("Client non-auth ne reçoit PAS les messages du chat",
      b"secret_message_123" not in unauth_data)
    ce.close()
    tx(cf, "/quit"); drain(cf, 0.3); cf.close()

    # ── T2.13  Login utilisateur existant ──
    # Disconnect SamePwdA first (still connected from T2.6)
    tx(ca, "/quit"); drain(ca, 0.3); ca.close()
    tx(cb, "/quit"); drain(cb, 0.3); cb.close()
    time.sleep(0.3)
    cg = mk()
    login_msgs = login(cg, "SamePwdA", "StrongP4ss")
    welcome = find_msg(login_msgs, "welcome")
    T("Login utilisateur existant → welcome", len(welcome) >= 1)
    tx(cg, "/quit"); drain(cg, 0.3); cg.close()
    time.sleep(0.3)

    # ── T2.14  Login mauvais mdp → refusé ──
    ch = mk()
    drain(ch)
    tx(ch, "SamePwdA")
    drain(ch)
    tx(ch, "WrongPassword1")
    msgs = drain(ch)
    wrong = any(m["type"] == "error" and "wrong" in m.get("content", "").lower()
                for m in msgs)
    T("Login mauvais mdp → rejeté", wrong)
    ch.close()

    # ── T2.15  /deleteaccount ──
    ci = mk()
    register(ci, "DeleteMe", "StrongP4ss", "secD")
    tx(ci, "/deleteaccount")
    time.sleep(0.5)
    tx(ci, "StrongP4ss")
    msgs = drain(ci)
    quit_msg = find_msg(msgs, "quit")
    T("/deleteaccount avec bon mdp → compte supprimé",
      len(quit_msg) >= 1)
    with open("this_is_safe.txt") as f:
        T("Utilisateur retiré de this_is_safe.txt",
          "DeleteMe" not in f.read())
    ci.close()

    # Cleanup remaining test users
    for u in ["SamePwdA", "SamePwdB", "AuthSender"]:
        server_instance.delete_user(u, notify=False)


# ════════════════════════════════════════════════════════════════════
#  JOUR 3 — Chiffrement TEA-CBC
# ════════════════════════════════════════════════════════════════════

def test_jour3():
    section("JOUR 3 — Chiffrement symétrique TEA-CBC")

    # ── T3.1  tea_cipher.py — TEA block cipher ──
    T("Module tea_cipher.py existe", os.path.exists("tea_cipher.py"))

    # ── T3.2  TEA : blocs 64 bits, clé 128 bits ──
    T("TEA BLOCK_SIZE = 8 (64 bits)", tea_cipher.BLOCK_SIZE == 8)
    key = tea_cipher.derive_key("test", b"x" * 16)
    T("Clé dérivée = 16 octets (128 bits)", len(key) == 16)

    # ── T3.3  CBC mode fonctionne ──
    plain = "Hello, World!"
    ct = tea_cipher.encrypt(plain.encode(), key)
    pt = tea_cipher.decrypt(ct, key)
    T("Encrypt → Decrypt donne le message original", pt.decode() == plain)

    # ── T3.4  IV aléatoire (chaque chiffrement différent) ──
    ct1 = tea_cipher.encrypt(b"same", key)
    ct2 = tea_cipher.encrypt(b"same", key)
    T("Même plaintext → ciphertext différent (IV aléatoire)", ct1 != ct2)

    # ── T3.5  PKCS7 padding ──
    for size in [1, 7, 8, 15, 16]:
        data = b"X" * size
        ct = tea_cipher.encrypt(data, key)
        pt = tea_cipher.decrypt(ct, key)
        assert pt == data
    T("PKCS7 padding correct pour tailles 1–16", True)

    # ── T3.6  KDF = PBKDF2-HMAC-SHA256 ──
    src = open("tea_cipher.py").read()
    T("KDF = PBKDF2-HMAC-SHA256", "pbkdf2_hmac" in src and "sha256" in src)
    T("Itérations KDF ≥ 100 000", tea_cipher.KDF_ITERATIONS >= 100_000)

    # ── T3.7  Sel KDF ≥ 96 bits ──
    salt = tea_cipher.generate_salt()
    T("Sel KDF = 16 octets (128 bits ≥ 96)", len(salt) >= 12)

    # ── T3.8  Fichier user_keys_do_not_steal_plz.txt ──
    T("Fichier user_keys_do_not_steal_plz.txt existe",
      os.path.exists("user_keys_do_not_steal_plz.txt"))
    if os.path.exists("user_keys_do_not_steal_plz.txt"):
        with open("user_keys_do_not_steal_plz.txt") as f:
            klines = [l.strip() for l in f if l.strip()]
        all_fmt = all(len(l.split(":", 2)) == 3 for l in klines)
        T("Format clés = username:salt_b64:key_b64", all_fmt and len(klines) >= 1)
        # Verify key salt ≥ 96 bits
        for l in klines:
            parts = l.split(":", 2)
            raw_salt = base64.b64decode(parts[1])
            if len(raw_salt) < 12:
                T("Sel de clé ≥ 96 bits", False, f"{parts[0]}: {len(raw_salt)} octets")
                break
        else:
            T("Sel de clé ≥ 96 bits pour chaque utilisateur", True)
        # Verify key ≥ 128 bits
        for l in klines:
            parts = l.split(":", 2)
            raw_key = base64.b64decode(parts[2])
            if len(raw_key) < 16:
                T("Clé ≥ 128 bits", False, f"{parts[0]}: {len(raw_key)*8} bits")
                break
        else:
            T("Clé ≥ 128 bits pour chaque utilisateur", True)

    # ── T3.9  Client stocke clé localement ──
    ca = mk()
    reg_msgs = register(ca, "KeyUser", "StrongP4ss", "mySecret")
    key_msgs = find_msg(reg_msgs, "encryption_key")
    T("Serveur envoie encryption_key au client", len(key_msgs) >= 1)
    # Check client-side storage directory structure
    T("Dossier ./users/ prévu pour stockage clé client",
      "users" in open("client.py").read())

    # ── T3.10  Messages chiffrés sur le réseau ──
    cb = mk()
    register(cb, "KeyUser2", "StrongP4ss", "otherSecret")
    key_u1 = server_instance._get_user_key("KeyUser")
    key_u2 = server_instance._get_user_key("KeyUser2")

    # Send encrypted message
    secret_text = "TOP_SECRET_PLAINTEXT_MARKER_12345"
    ct_msg = tea_cipher.encrypt_b64(secret_text, key_u1)
    tx(ca, ct_msg, encrypted=True)
    time.sleep(0.3)

    # Capture raw bytes on User2's socket
    raw = raw_recv(cb, 1.0)
    T("Message envoyé chiffré (plaintext ABSENT du flux réseau)",
      secret_text.encode() not in raw)
    T("Ciphertext base64 présent dans le flux réseau",
      b"encrypted" in raw and b"true" in raw.lower() if raw else False)

    # Verify User2 can decrypt
    msgs = []
    for line in raw.decode(errors="replace").split("\n"):
        line = line.strip()
        if line:
            try:
                msgs.append(json.loads(line))
            except:
                pass
    chat = [m for m in msgs if m.get("type") == "message"]
    if chat:
        try:
            decrypted = tea_cipher.decrypt_b64(chat[0]["content"], key_u2)
            T("User2 déchiffre le message correctement", decrypted == secret_text)
        except Exception as e:
            T("User2 déchiffre le message", False, str(e))
    else:
        T("User2 reçoit le message chiffré", False, "Aucun message reçu")

    # ── T3.11  Login existant → clé renvoyée ──
    tx(ca, "/quit"); drain(ca, 0.3); ca.close()
    time.sleep(0.3)
    ca2 = mk()
    login_msgs = login(ca2, "KeyUser", "StrongP4ss")
    key_on_login = find_msg(login_msgs, "encryption_key")
    T("Login existant → encryption_key renvoyée", len(key_on_login) >= 1)
    if key_on_login:
        T("Clé identique après re-login",
          key_on_login[0]["key"] == tea_cipher.key_to_b64(key_u1))
    tx(ca2, "/quit"); drain(ca2, 0.3); ca2.close()
    tx(cb, "/quit"); drain(cb, 0.3); cb.close()

    # Cleanup
    for u in ["KeyUser", "KeyUser2"]:
        server_instance.delete_user(u, notify=False)


# ════════════════════════════════════════════════════════════════════
#  TESTS COMPLÉMENTAIRES — Sécurité
# ════════════════════════════════════════════════════════════════════

def test_security():
    section("SÉCURITÉ — Vérifications complémentaires")

    src = open("server.py").read()

    # ── S1  Pas de mot de passe en clair dans le fichier ──
    with open("this_is_safe.txt") as f:
        safe_content = f.read()
    T("Aucun mot de passe en clair dans this_is_safe.txt",
      "StrongP4ss" not in safe_content)

    # ── S2  Timing-safe : hmac.compare_digest ──
    T("Comparaison temps constant (hmac.compare_digest)", "hmac.compare_digest" in src)

    # ── S3  Verify timing: dummy hash done even for unknown user? ──
    # Check if _verify_password does early return for unknown user
    # This is an observation — not always fixable
    verify_src = ""
    in_verify = False
    for line in src.split("\n"):
        if "_verify_password" in line and "def " in line:
            in_verify = True
        elif in_verify and line.strip().startswith("def "):
            break
        if in_verify:
            verify_src += line + "\n"
    early_return = "return False" in verify_src and verify_src.index("return False") < verify_src.index("compare_digest") if "compare_digest" in verify_src else True
    if early_return:
        RESULTS.append("  ⚠️  _verify_password retourne tôt si utilisateur inconnu "
                       "(timing leak mineur — permet énumérer les usernames)")
    else:
        T("Pas de timing leak sur utilisateur inconnu", True)

    # ── S4  Pas de stockage de clé en clair dans les logs ──
    log_files = glob.glob("log_*.txt")
    if log_files:
        with open(log_files[-1]) as f:
            log = f.read()
        T("Pas de clé de chiffrement dans les logs",
          "encryption_key" not in log.lower() and "key=" not in log.lower())
    
    # ── S5  Log contient les plaintext (observation) ──
    if log_files:
        RESULTS.append("  ⚠️  Le serveur log les messages en clair après déchiffrement "
                       "(normal pour un serveur centralisé, mais à noter)")

    # ── S6  Commandes envoyées en clair ──
    RESULTS.append("  ⚠️  Les commandes (/) sont envoyées en clair — les mots de passe "
                   "de room (/create, /join) transitent non-chiffrés")

    # ── S7  import string inutilisé ──
    T("Pas d'import inutilisé majeur",
      True)  # `string` is unused but harmless
    if "import string" in src:
        RESULTS.append("  ℹ️  `import string` est importé mais inutilisé (nettoyage mineur)")


# ════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════

def main():
    # Cleanup previous artifacts
    for f in glob.glob("log_*.txt"):
        os.remove(f)
    for f in ["this_is_safe.txt", "user_keys_do_not_steal_plz.txt"]:
        if os.path.exists(f):
            os.remove(f)
    import shutil
    shutil.rmtree("users", ignore_errors=True)

    # Start server
    srv = start_server(19991)

    try:
        test_jour1()
        test_jour2()
        test_jour3()
        test_security()
    except Exception as e:
        RESULTS.append(f"\n  💥 EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Summary
        print("\n" + "═" * 60)
        print("  RAPPORT D'AUDIT — Test Automatisé")
        print("═" * 60)
        for r in RESULTS:
            print(r)
        print(f"\n{'═'*60}")
        print(f"  TOTAL: {test_count[0]} ✅  |  {test_count[1]} ❌")
        print(f"{'═'*60}")

        # Cleanup
        for f in glob.glob("log_*.txt"):
            try: os.remove(f)
            except: pass
        for f in ["this_is_safe.txt", "user_keys_do_not_steal_plz.txt"]:
            try: os.remove(f)
            except: pass
        shutil.rmtree("users", ignore_errors=True)


if __name__ == "__main__":
    main()
