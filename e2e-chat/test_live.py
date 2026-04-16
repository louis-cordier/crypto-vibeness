#!/usr/bin/env python3
"""
Crypto-Vibe — Suite de tests EN DIRECT, un à un.
Chaque test s'affiche immédiatement avec résultat et contexte.

Lancer depuis e2e-chat/ :  python3 test_live.py
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
import shutil

sys.path.insert(0, ".")
from server import ChatServer, DEFAULT_PORT
import tea_cipher
import kem as kem_mod

# ── Palette ANSI ─────────────────────────────────────────────────────
GRN  = "\033[92m"
RED  = "\033[91m"
YEL  = "\033[93m"
BLU  = "\033[94m"
CYN  = "\033[96m"
MAG  = "\033[95m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

PORT = 19993
server_instance: ChatServer | None = None
_passed = 0
_failed = 0
_warnings: list[str] = []

# Clé RSA partagée pour tous les tests (générée une seule fois)
TEST_PUB: tuple[int, int] | None = None
TEST_PRIV: tuple[int, int] | None = None

COLORS_REF = [
    "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m",
    "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m",
]

# ── Affichage ─────────────────────────────────────────────────────────

def banner():
    print(f"\n{BOLD}{BLU}╔{'═'*58}╗{RST}")
    print(f"{BOLD}{BLU}║{'CRYPTO-VIBE  ·  TESTS EN DIRECT'.center(58)}║{RST}")
    print(f"{BOLD}{BLU}╚{'═'*58}╝{RST}\n")


def section(title: str):
    print(f"\n{BOLD}{CYN}╔{'═'*58}╗{RST}")
    print(f"{BOLD}{CYN}║  {title:<56}║{RST}")
    print(f"{BOLD}{CYN}╚{'═'*58}╝{RST}")


def T(name: str, condition: bool, detail: str = ""):
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  {GRN}✅  {name}{RST}")
    else:
        _failed += 1
        print(f"  {RED}❌  {name}{RST}")
        if detail:
            print(f"       {DIM}↳ {detail}{RST}")
    sys.stdout.flush()


def W(msg: str):
    _warnings.append(msg)
    print(f"  {YEL}⚠️   {msg}{RST}")
    sys.stdout.flush()


def I(msg: str):
    print(f"  {DIM}ℹ   {msg}{RST}")
    sys.stdout.flush()


def doing(msg: str):
    print(f"\n  {MAG}▶  {msg}{RST}")
    sys.stdout.flush()


# ── Helpers réseau bas niveau ─────────────────────────────────────────

def mk() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", PORT))
    s.settimeout(5)
    return s


def _tx_raw(s: socket.socket, data: dict):
    s.sendall((json.dumps(data) + "\n").encode())


def tx(s: socket.socket, content: str, encrypted: bool = False):
    msg: dict = {"content": content}
    if encrypted:
        msg["encrypted"] = True
    _tx_raw(s, msg)


def tx_signed(s: socket.socket, plaintext: str, session_key: bytes,
              room_key: bytes | None = None):
    """Chiffre + signe le message (comme le vrai client) et l'envoie.

    Si room_key est fourni, double-chiffrement :
      room_ct = encrypt(plaintext, room_key)  ← le serveur ne voit que ça
      sig     = sign(room_ct)                 ← signé sur room_ct
      outer   = encrypt(room_ct, session_key) ← transport
    Sinon, chiffrement simple (room ouverte) :
      sig     = sign(plaintext)
      outer   = encrypt(plaintext, session_key)
    """
    if room_key:
        room_ct = tea_cipher.encrypt_b64(plaintext, room_key)
        sig = kem_mod.rsa_sign(room_ct.encode("utf-8"), TEST_PRIV)
        sig_b64 = base64.b64encode(sig).decode()
        outer = tea_cipher.encrypt_b64(room_ct, session_key)
        _tx_raw(s, {"content": outer, "encrypted": True,
                    "room_encrypted": True, "signature": sig_b64})
    else:
        sig = kem_mod.rsa_sign(plaintext.encode("utf-8"), TEST_PRIV)
        sig_b64 = base64.b64encode(sig).decode()
        encrypted = tea_cipher.encrypt_b64(plaintext, session_key)
        _tx_raw(s, {"content": encrypted, "encrypted": True, "signature": sig_b64})


def drain(s: socket.socket, t: float = 2.0) -> list[dict]:
    """Lit tous les messages disponibles jusqu'au timeout."""
    msgs: list[dict] = []
    buf = ""
    s.settimeout(t)
    try:
        while True:
            chunk = s.recv(4096).decode(errors="replace")
            if not chunk:
                break
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                try:
                    msgs.append(json.loads(line))
                except Exception:
                    pass
    except socket.timeout:
        pass
    return msgs


def raw_recv(s: socket.socket, t: float = 1.5) -> bytes:
    """Reçoit les données brutes (niveau TCP)."""
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


def find_msg(msgs: list[dict], msg_type: str) -> list[dict]:
    return [m for m in msgs if m.get("type") == msg_type]


def _handle_kem(s: socket.socket, msgs: list[dict]) -> bytes | None:
    """Si msgs contient un kem_request, répond avec notre pubkey et retourne la session key."""
    kem_reqs = find_msg(msgs, "kem_request")
    if not kem_reqs:
        return None
    pub_dict = kem_mod.pubkey_to_dict(TEST_PUB)
    pub_dict["type"] = "kem_pubkey"
    _tx_raw(s, pub_dict)
    # Lit la réponse (kem_response + welcome)
    resp_msgs = drain(s, 3.0)
    kem_resps = find_msg(resp_msgs, "kem_response")
    session_key = None
    if kem_resps:
        ct = kem_mod.ct_from_b64(kem_resps[0]["ciphertext"])
        session_key = kem_mod.decapsulate(ct, TEST_PRIV)
    return session_key, resp_msgs


# ── Helpers de haut niveau : register / login ─────────────────────────

def do_register(s: socket.socket, username: str, password: str) -> tuple[list[dict], bytes | None]:
    """
    Inscription complète avec échange KEM.
    Retourne (all_msgs, session_key).
    """
    all_msgs: list[dict] = []

    all_msgs += drain(s)                  # prompt username
    tx(s, username)
    all_msgs += drain(s)                  # system "new user" + rules + auth_prompt
    tx(s, password)
    all_msgs += drain(s)                  # auth_prompt (confirm)
    tx(s, password)                       # confirmation
    phase_msgs = drain(s, 3.0)            # strength msg + kem_request
    all_msgs += phase_msgs

    result = _handle_kem(s, phase_msgs)
    session_key = None
    if result is not None:
        session_key, post_msgs = result
        all_msgs += post_msgs

    return all_msgs, session_key


def do_login(s: socket.socket, username: str, password: str) -> tuple[list[dict], bytes | None]:
    """
    Login utilisateur existant avec échange KEM.
    Retourne (all_msgs, session_key).
    """
    all_msgs: list[dict] = []

    all_msgs += drain(s)                  # prompt username
    tx(s, username)
    all_msgs += drain(s)                  # auth_prompt password
    tx(s, password)
    phase_msgs = drain(s, 3.0)            # kem_request (après vérification mdp)
    all_msgs += phase_msgs

    result = _handle_kem(s, phase_msgs)
    session_key = None
    if result is not None:
        session_key, post_msgs = result
        all_msgs += post_msgs

    return all_msgs, session_key


def quit_client(s: socket.socket):
    try:
        tx(s, "/quit")
        drain(s, 0.3)
        s.close()
    except Exception:
        pass


# ── Serveur ──────────────────────────────────────────────────────────

def start_server():
    global server_instance
    server_instance = ChatServer(PORT)
    threading.Thread(target=server_instance.start, daemon=True).start()
    time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════
#  JOUR 1 — Chat IRC de base (Partie 1)
# ═══════════════════════════════════════════════════════════════════

def test_jour1():
    section("JOUR 1 — Chat IRC multi-utilisateurs")

    doing("Port par défaut (5555)")
    T("DEFAULT_PORT = 5555", DEFAULT_PORT == 5555)
    src_srv = open("server.py").read()
    T("Port configurable via sys.argv", "sys.argv" in src_srv)

    doing("Connexion simultanée de deux clients")
    c1 = mk(); c2 = mk()
    msgs1, key1 = do_register(c1, "Alice_T1", "StrongP4ss")
    msgs2, key2 = do_register(c2, "Bob_T1",   "StrongP4ss")
    in_clients = ("Alice_T1" in server_instance.clients and
                  "Bob_T1"   in server_instance.clients)
    T("Deux clients connectés simultanément", in_clients)
    T("Session key Alice établie via KEM", key1 is not None)
    T("Session key Bob   établie via KEM", key2 is not None)

    doing("Unicité des pseudos")
    c3 = mk()
    drain(c3)
    tx(c3, "Alice_T1")
    resp = drain(c3)
    already = any(m.get("type") == "error" and "already" in m.get("content", "").lower()
                  for m in resp)
    T("Pseudo déjà connecté → erreur 'already'", already)
    c3.close()

    doing("Room par défaut = 'general'")
    with server_instance.lock:
        room_a = server_instance.clients.get("Alice_T1", {}).get("room")
    T("Alice est bien dans la room 'general' par défaut", room_a == "general")

    doing("Création de room avec /create")
    tx(c1, "/create salon_test"); drain(c1)
    with server_instance.lock:
        room_ok = "salon_test" in server_instance.rooms
    T("Room 'salon_test' créée avec /create", room_ok)

    doing("Room protégée par mot de passe")
    tx(c1, "/create secret_room mdp123"); drain(c1)
    with server_instance.lock:
        pwd_ok = server_instance.rooms.get("secret_room", {}).get("password") == "mdp123"
    T("Room 'secret_room' créée avec mot de passe 'mdp123'", pwd_ok)

    doing("Rejoindre une room avec /join")
    tx(c1, "/join salon_test"); drain(c1)
    with server_instance.lock:
        moved = server_instance.clients.get("Alice_T1", {}).get("room") == "salon_test"
    T("Alice a rejoint 'salon_test'", moved)

    doing("Join room protégée SANS mot de passe → refusé")
    tx(c2, "/join secret_room"); msgs = drain(c2)
    has_err = any(m.get("type") == "error" and
                  any(w in m.get("content", "").lower() for w in ["incorrect", "password"])
                  for m in msgs)
    T("Rejoindre une room protégée sans mdp → erreur", has_err)

    doing("Join room protégée avec le BON mot de passe")
    tx(c2, "/join secret_room mdp123"); drain(c2)
    with server_instance.lock:
        joined = server_instance.clients.get("Bob_T1", {}).get("room") == "secret_room"
    T("Bob a rejoint 'secret_room' avec le bon mdp", joined)

    doing("Isolation des rooms (Alice dans salon_test, Bob dans secret_room)")
    if key1:
        ct = tea_cipher.encrypt_b64("msg_isole_salon_test", key1)
        tx(c1, ct, encrypted=True)
        time.sleep(0.4)
        bob_msgs = drain(c2, 0.8)
        chat_bob = [m for m in bob_msgs if m.get("type") == "message"]
        T("Bob ne reçoit PAS le message d'Alice (rooms différentes)", len(chat_bob) == 0)
    else:
        T("Isolation des rooms", False, "Session key Alice manquante")

    doing("Timestamps HH:MM:SS sur les messages (Bob rejoint salon_test)")
    tx(c2, "/leave"); drain(c2)
    tx(c2, "/join salon_test"); drain(c2)
    if key1:
        tx(c1, tea_cipher.encrypt_b64("test_timestamp_msg", key1), encrypted=True)
        time.sleep(0.4)
        msgs = drain(c2, 1.0)
        chat = [m for m in msgs if m.get("type") == "message"]
        has_ts = any("timestamp" in m and re.match(r"\d{2}:\d{2}:\d{2}", m.get("timestamp", ""))
                     for m in chat)
        T("Timestamp HH:MM:SS présent dans les messages", has_ts)
    else:
        T("Timestamps HH:MM:SS", False, "Session key Alice manquante")

    doing("Couleur déterministe par pseudo (MD5 du username)")
    c_a1 = ChatServer._color_for("Alice_T1")
    c_a2 = ChatServer._color_for("Alice_T1")
    expected = COLORS_REF[int(hashlib.md5("Alice_T1".encode()).hexdigest(), 16) % len(COLORS_REF)]
    T("Même pseudo → même couleur (déterministe)", c_a1 == c_a2)
    T("Couleur calculée via MD5 du pseudo",        c_a1 == expected)

    doing("Fichier de log horodaté log_YYYY-MM-DD_HH-MM-SS.txt")
    log_files = glob.glob("log_*.txt")
    T("Fichier log créé", len(log_files) >= 1)
    if log_files:
        fname = os.path.basename(log_files[-1])
        T("Format du nom de log correct",
          bool(re.match(r"log_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt", fname)))
        log_content = open(log_files[-1]).read()
        T("Log contient les connexions", any(w in log_content for w in ["connect", "Connect", "New"]))
        T("Log contient des événements de room", any(r in log_content for r in ["salon_test", "general", "room"]))

    doing("Commande /rooms — liste des rooms avec flag 'protected'")
    tx(c1, "/rooms"); msgs = drain(c1)
    room_list = find_msg(msgs, "room_list")
    if room_list:
        rooms_data = room_list[0].get("rooms", [])
        secret = [r for r in rooms_data if r["name"] == "secret_room"]
        general = [r for r in rooms_data if r["name"] == "general"]
        T("Room protégée marquée 'protected: true'",
          len(secret) == 1 and secret[0].get("protected") is True)
        T("Room non-protégée marquée 'protected: false'",
          len(general) == 1 and general[0].get("protected") is False)
    else:
        T("/rooms renvoie un message room_list", False, "Aucun room_list reçu")

    doing("Commande /who — liste des utilisateurs de la room")
    tx(c1, "/who"); msgs = drain(c1)
    who_msgs = [m for m in msgs if m.get("type") == "system" and "Users in" in m.get("content", "")]
    T("/who liste les utilisateurs de la room", len(who_msgs) >= 1)

    doing("Commande /leave — retour à 'general'")
    tx(c1, "/leave"); drain(c1)
    with server_instance.lock:
        back = server_instance.clients.get("Alice_T1", {}).get("room") == "general"
    T("/leave ramène Alice à 'general'", back)

    doing("Commande /quit — déconnexion propre")
    tx(c2, "/quit"); time.sleep(0.4); drain(c2, 0.3)
    with server_instance.lock:
        gone = "Bob_T1" not in server_instance.clients
    T("/quit déconnecte le client proprement", gone)
    c2.close()

    quit_client(c1)
    time.sleep(0.3)


# ═══════════════════════════════════════════════════════════════════
#  JOUR 2 — Authentification MD5 + sel (Partie 2)
# ═══════════════════════════════════════════════════════════════════

def test_jour2():
    section("JOUR 2 — Authentification MD5 + sel")

    doing("Existence et format de this_is_safe.txt")
    T("Fichier this_is_safe.txt existe", os.path.exists("this_is_safe.txt"))
    with open("this_is_safe.txt") as f:
        lines = [l.strip() for l in f if l.strip()]
    all_valid = all(len(l.split(":", 2)) == 3 for l in lines)
    T(f"Format username:salt:hash respecté ({len(lines)} entrée(s))",
      all_valid and len(lines) >= 1)

    doing("Hash en base64 (MD5 = 16 octets) et sel ≥ 96 bits")
    all_b64 = True
    all_salt = True
    for l in lines:
        u, salt_b64, hash_b64 = l.split(":", 2)
        try:
            if len(base64.b64decode(hash_b64)) != 16:
                all_b64 = False
            if len(base64.b64decode(salt_b64)) < 12:
                all_salt = False
        except Exception:
            all_b64 = all_salt = False
    T("Hash MD5 encodé en base64 (16 octets)", all_b64)
    T("Sel ≥ 96 bits (12 octets) par utilisateur",     all_salt)

    doing("Algorithme MD5 utilisé dans server.py")
    T("MD5 via hashlib utilisé", "md5" in open("server.py").read().lower())

    doing("Même mot de passe → sels ET hashs différents (sel unique par user)")
    ca = mk(); cb = mk()
    _, ka = do_register(ca, "SamePwd_A", "StrongP4ss")
    _, kb = do_register(cb, "SamePwd_B", "StrongP4ss")
    time.sleep(0.3)
    salt_a = hash_a = salt_b = hash_b = None
    for l in open("this_is_safe.txt").read().strip().split("\n"):
        parts = l.split(":", 2)
        if parts[0] == "SamePwd_A": salt_a, hash_a = parts[1], parts[2]
        elif parts[0] == "SamePwd_B": salt_b, hash_b = parts[1], parts[2]
    T("Même mdp → sels différents",  salt_a != salt_b and salt_a is not None)
    T("Même mdp → hashs différents", hash_a != hash_b and hash_a is not None)

    doing("Vérification de password_rules.json (≥ 3 règles)")
    import json as _json
    T("Fichier password_rules.json existe", os.path.exists("password_rules.json"))
    rules = _json.load(open("password_rules.json")).get("rules", [])
    T(f"Au moins 3 règles définies ({len(rules)} trouvée(s))", len(rules) >= 3)
    T("Règles chargées dans server_instance au démarrage",
      len(server_instance.password_rules) >= 3)

    doing("Mot de passe trop faible rejeté")
    cc = mk()
    drain(cc)
    tx(cc, "WeakUser_Test")
    drain(cc)
    tx(cc, "abc")   # trop court, pas de maj, pas de chiffre
    msgs = drain(cc, 2.0)
    rejected = any(m.get("type") == "error" and "rejected" in m.get("content", "").lower()
                   for m in msgs)
    T("Mot de passe 'abc' (< 8 chars, sans maj, sans chiffre) → rejeté", rejected)
    cc.close()

    doing("Indicateur de force (entropie Shannon) affiché à l'inscription")
    cd = mk()
    msgs_d, _ = do_register(cd, "EntropyUser_T2", "Str0ng@Pass!")
    has_strength = any("strength" in m.get("content", "").lower()
                       for m in msgs_d if m.get("type") == "system")
    has_bits     = any("bits" in m.get("content", "").lower() for m in msgs_d)
    T("Indicateur de force du mot de passe affiché", has_strength)
    T("Entropie en bits affichée",                   has_bits)
    quit_client(cd)

    doing("Vérification temps constant (hmac.compare_digest)")
    T("hmac.compare_digest utilisé (résistance aux timing attacks)",
      "hmac.compare_digest" in open("server.py").read())

    doing("Client non-authentifié ne reçoit PAS les messages du chat")
    ce = mk()
    drain(ce, 0.5)   # reçoit le prompt username, ne répond pas
    cf = mk()
    _, key_s = do_register(cf, "AuthSender_T2", "StrongP4ss")
    if key_s:
        tx(cf, tea_cipher.encrypt_b64("secret_T2_unauth", key_s), encrypted=True)
    time.sleep(0.5)
    unauth_data = raw_recv(ce, 0.5)
    T("Client non-auth ne reçoit PAS les messages du chat",
      b"secret_T2_unauth" not in unauth_data)
    ce.close()
    quit_client(cf)

    doing("Login d'un utilisateur existant")
    quit_client(ca); quit_client(cb); time.sleep(0.3)
    cg = mk()
    login_msgs, key_g = do_login(cg, "SamePwd_A", "StrongP4ss")
    welcome = find_msg(login_msgs, "welcome")
    T("Login existant → message 'welcome' reçu",   len(welcome) >= 1)
    T("Session key établie via KEM sur re-login",  key_g is not None)
    quit_client(cg); time.sleep(0.3)

    doing("Login avec un mauvais mot de passe → refusé")
    ch = mk()
    drain(ch); tx(ch, "SamePwd_A")
    drain(ch); tx(ch, "WrongP4ssword!")
    msgs = drain(ch, 2.0)
    wrong = any(m.get("type") == "error" and "wrong" in m.get("content", "").lower()
                for m in msgs)
    T("Login mauvais mdp → erreur 'wrong'", wrong)
    ch.close()

    doing("Commande /deleteaccount — suppression du compte")
    ci = mk()
    _, _ = do_register(ci, "DeleteMe_T2", "StrongP4ss")
    tx(ci, "/deleteaccount"); time.sleep(0.5)
    tx(ci, "StrongP4ss")
    msgs = drain(ci, 2.0)
    quit_msg = find_msg(msgs, "quit")
    T("/deleteaccount + bon mdp → déconnexion (message 'quit')", len(quit_msg) >= 1)
    T("Utilisateur retiré de this_is_safe.txt",
      "DeleteMe_T2" not in open("this_is_safe.txt").read())
    ci.close()

    # Nettoyage
    for u in ["SamePwd_A", "SamePwd_B", "AuthSender_T2", "EntropyUser_T2"]:
        server_instance.delete_user(u, notify=False)


# ═══════════════════════════════════════════════════════════════════
#  JOUR 3 — Chiffrement TEA-CBC + RSA-KEM (Parties 1 & 2)
# ═══════════════════════════════════════════════════════════════════

def test_jour3():
    section("JOUR 3 — Chiffrement TEA-CBC + RSA-KEM")

    doing("Module tea_cipher.py — constantes et fonctions")
    T("Module tea_cipher.py présent", os.path.exists("tea_cipher.py"))
    T("BLOCK_SIZE = 8 (blocs TEA de 64 bits)", tea_cipher.BLOCK_SIZE == 8)
    ref_key = tea_cipher.derive_key("test_secret", tea_cipher.generate_salt())
    T("Clé dérivée = 16 octets (128 bits)", len(ref_key) == 16)

    doing("Encrypt → Decrypt restituent le message original")
    plain = "Hello, Crypto-Vibe! 🔐"
    ct = tea_cipher.encrypt(plain.encode("utf-8"), ref_key)
    pt = tea_cipher.decrypt(ct, ref_key)
    T("Decrypt(Encrypt(msg)) == msg", pt.decode("utf-8") == plain)

    doing("IV aléatoire — même plaintext → ciphertexts différents")
    ct1 = tea_cipher.encrypt(b"same_data", ref_key)
    ct2 = tea_cipher.encrypt(b"same_data", ref_key)
    T("Même plaintext → ciphertext différent (IV aléatoire)", ct1 != ct2)

    doing("Padding PKCS7 — aller-retour pour tailles 1 à 16 octets")
    ok = True
    for size in [1, 7, 8, 9, 15, 16]:
        data = b"X" * size
        if tea_cipher.decrypt(tea_cipher.encrypt(data, ref_key), ref_key) != data:
            ok = False
    T("Padding PKCS7 correct pour tailles 1–16 octets", ok)

    doing("KDF = PBKDF2-HMAC-SHA256 avec 100 000 itérations")
    src_tea = open("tea_cipher.py").read()
    T("KDF = PBKDF2-HMAC-SHA256",         "pbkdf2_hmac" in src_tea and "sha256" in src_tea)
    T(f"Itérations KDF ≥ 100 000 ({tea_cipher.KDF_ITERATIONS:,})",
      tea_cipher.KDF_ITERATIONS >= 100_000)
    salt_sample = tea_cipher.generate_salt()
    T(f"Sel KDF ≥ 96 bits ({len(salt_sample)*8} bits trouvés)", len(salt_sample) >= 12)

    doing("Module kem.py — RSA-1024 KEM")
    T("Module kem.py présent", os.path.exists("kem.py"))
    T("RSA-1024 bits implémenté", "1024" in open("kem.py").read())
    T("Fonctions encapsulate / decapsulate présentes",
      hasattr(kem_mod, "encapsulate") and hasattr(kem_mod, "decapsulate"))
    # Vérifier le round-trip KEM avec la paire de test
    ct_test, sk_enc = kem_mod.encapsulate(TEST_PUB)
    sk_dec = kem_mod.decapsulate(ct_test, TEST_PRIV)
    T("KEM round-trip : encapsulate → decapsulate → même clé", sk_enc == sk_dec)
    T("Clé KEM = 16 octets (128 bits)", len(sk_enc) == 16)

    doing("Clé RSA client stockée localement dans ./users/<username>/")
    src_cli = open("client.py").read()
    T("Client sauvegarde la clé privée RSA localement",
      "save_private_key" in src_cli and "users" in src_cli)
    T("Client recharge la clé existante si disponible",
      "load_private_key" in src_cli)

    doing("Inscription : session key établie via KEM")
    ca = mk()
    msgs_a, key_a = do_register(ca, "KeyUser_T3", "StrongP4ss")
    kem_resp_present = any(m.get("type") == "kem_response" for m in msgs_a)
    T("Serveur envoie kem_response (ciphertext) au client", kem_resp_present)
    T("Client décapsule → session key obtenue",              key_a is not None)

    doing("Messages chiffrés sur le réseau — plaintext absent du flux TCP")
    cb = mk()
    _, key_b = do_register(cb, "KeyUser2_T3", "StrongP4ss")
    secret = "PLAINTEXT_MARKER_42_XYZZY"
    if key_a:
        ct_msg = tea_cipher.encrypt_b64(secret, key_a)
        tx(ca, ct_msg, encrypted=True)
        time.sleep(0.4)
        raw = raw_recv(cb, 1.0)
        T("Plaintext ABSENT du flux réseau",       secret.encode() not in raw)
        T("Champ 'encrypted: true' présent dans le flux", b'"encrypted"' in raw)

        doing("Le destinataire déchiffre correctement le message avec sa propre clé")
        if key_b:
            chat_raw = [json.loads(l) for l in raw.decode(errors="replace").split("\n")
                        if l.strip() and l.strip().startswith("{")]
            chat_msgs = [m for m in chat_raw if m.get("type") == "message"]
            if chat_msgs:
                try:
                    decrypted = tea_cipher.decrypt_b64(chat_msgs[0]["content"], key_b)
                    T("Destinataire déchiffre le message avec sa session key", decrypted == secret)
                except Exception as e:
                    T("Destinataire déchiffre le message", False, str(e))
            else:
                T("Destinataire reçoit le message chiffré", False, "Aucun message reçu")
        else:
            T("Destinataire déchiffre (key_b manquante)", False, "Session key B non établie")
    else:
        T("Test chiffrement réseau", False, "Session key A manquante")

    doing("Re-login → nouvelle session key établie via KEM")
    quit_client(ca); time.sleep(0.3)
    ca2 = mk()
    login_msgs, key_a2 = do_login(ca2, "KeyUser_T3", "StrongP4ss")
    has_kem_resp = any(m.get("type") == "kem_response" for m in login_msgs)
    T("Re-login → kem_response reçu (nouvelle session key via KEM)", has_kem_resp)
    T("Nouvelle session key obtenue après re-login",                  key_a2 is not None)
    quit_client(ca2); quit_client(cb)

    for u in ["KeyUser_T3", "KeyUser2_T3"]:
        server_instance.delete_user(u, notify=False)


# ═══════════════════════════════════════════════════════════════════
#  JOUR 4 — Messages privés (DM) et groupes protégés signés
# ═══════════════════════════════════════════════════════════════════

def test_dm_and_protected():
    """Test DMs E2EE et enforcement signatures dans les rooms protégées."""
    section("JOUR 4 — Messages privés (DM) + groupes protégés signés")

    srv_src = open("server.py").read()
    cli_src = open("client.py").read()

    # ── Vérifications statiques ─────────────────────────────────────
    doing("Architecture DM chiffré + signé")
    T("Client implémente /dm avec chiffrement E2EE", '"type": "dm"' in cli_src)
    T("Client signe le contenu chiffré du DM",
      'rsa_sign' in cli_src and '"type": "dm"' in cli_src)
    T("Client vérifie la signature DM reçue",
      'rsa_verify' in cli_src and 'dm' in cli_src)
    T("Serveur relaie les DM avec champ 'from'",
      'fwd["from"] = username' in srv_src or '"from"' in srv_src)
    T("Serveur gère dm_key_exchange pour canal sécurisé",
      '"dm_key_exchange"' in srv_src)

    doing("Enforcement signatures dans les rooms protégées")
    T("Serveur lit le password de la room avant broadcast",
      'room_pwd' in srv_src or 'room_password' in srv_src)
    T("Serveur rejette les messages sans signature dans room protégée",
      '"Messages in protected rooms must be signed."' in srv_src
      or 'must be signed' in srv_src)
    T("Serveur valide la signature RSA avant broadcast",
      'rsa_verify' in srv_src and 'pubkey_from_dict' in srv_src)
    T("Serveur rejette les signatures invalides",
      'Invalid signature' in srv_src)

    # ── Tests fonctionnels : room protégée ─────────────────────────
    doing("Room protégée — message NON signé rejeté")
    ca = mk()
    cb = mk()
    _, key_a = do_register(ca, "DM_Alice", "StrongP4ss1")
    _, key_b = do_register(cb, "DM_Bob",   "StrongP4ss1")

    # Alice crée une room protégée et s'y rend
    tx(ca, "/create prot_room secretpwd")
    time.sleep(0.2)
    drain(ca, 0.5)
    tx(ca, "/join prot_room secretpwd")
    time.sleep(0.2)
    drain(ca, 0.5)

    # Bob rejoint la même room
    tx(cb, "/join prot_room secretpwd")
    time.sleep(0.2)
    drain(cb, 0.5)

    # Alice envoie un message sans signature → doit être rejeté
    if key_a:
        encrypted_only = tea_cipher.encrypt_b64("test_no_sig", key_a)
        _tx_raw(ca, {"content": encrypted_only, "encrypted": True})
        time.sleep(0.3)
        bob_msgs = drain(cb, 1.0)
        alice_reply = drain(ca, 0.5)
        bob_got_msg = any(m.get("type") == "message" for m in bob_msgs)
        alice_got_err = any(m.get("type") == "error" and "sign" in m.get("content","").lower()
                            for m in alice_reply)
        T("Message sans signature rejeté dans room protégée", not bob_got_msg)
        T("Serveur retourne une erreur 'must be signed'",     alice_got_err)

    doing("Room protégée — message signé + double chiffrement (room_key)")
    if key_a and key_b:
        # Dériver la room_key identique des deux côtés (comme le vrai client)
        room_password = "secretpwd"
        room_name     = "prot_room"
        room_key = tea_cipher.derive_key(room_password, room_name.encode())

        # Alice envoie avec double chiffrement
        secret_msg = "hello_signed_msg"
        tx_signed(ca, secret_msg, key_a, room_key=room_key)
        time.sleep(0.3)
        bob_msgs = drain(cb, 1.0)
        signed_msgs = [m for m in bob_msgs
                       if m.get("type") == "message" and m.get("signature")]
        T("Bob reçoit le message signé dans la room protégée",  len(signed_msgs) > 0)
        if signed_msgs:
            m = signed_msgs[0]
            T("Message chiffré (encrypted: true)",    m.get("encrypted") is True)
            T("Flag room_encrypted présent",           m.get("room_encrypted") is True)
            T("Signature présente dans le message",    m.get("signature") is not None)
            T("Clé publique de l'expéditeur incluse",  m.get("sender_pubkey") is not None)
            T("Plaintext ABSENT du message réseau (double chiffrement)",
              secret_msg not in m.get("content", ""))

            # Bob déchiffre couche session puis couche room
            if m.get("sender_pubkey") and m.get("signature"):
                try:
                    room_ct = tea_cipher.decrypt_b64(m["content"], key_b)  # couche session
                    plaintext_recv = tea_cipher.decrypt_b64(room_ct, room_key)  # couche room
                    T("Bob déchiffre le double chiffrement (texte lisible)",
                      plaintext_recv == secret_msg)
                    # Signature était sur room_ct (pas sur le plaintext)
                    pub = kem_mod.pubkey_from_dict(m["sender_pubkey"])
                    sig = base64.b64decode(m["signature"])
                    T("Bob vérifie la signature RSA de Alice (sur room_ct)",
                      kem_mod.rsa_verify(room_ct.encode(), sig, pub))
                except Exception as e:
                    T("Bob déchiffre + vérifie (double couche)", False, str(e))

        # Vérifier dans le log serveur que le plaintext n'est PAS visible
        doing("Serveur — log protégé (plaintext invisible)")
        import glob as _glob
        log_files = sorted(_glob.glob("log_*.txt"))
        if log_files:
            log_content = open(log_files[-1]).read()
            T("Plaintext ABSENT des logs serveur (double chiffrement efficace)",
              secret_msg not in log_content)
            T("Serveur log '[🔒 encrypted message]' pour les rooms protégées",
              "encrypted message" in log_content or "🔒" in log_content)

    # ── Tests fonctionnels : DM ─────────────────────────────────────
    doing("Message privé /dm — chiffré + signé")
    # Envoyer un DM directement (type='dm' raw, comme le vrai client le ferait)
    # Sans échange de clé préalable, on envoie un dm_key_exchange puis un dm
    if key_a:
        # Simuler dm_key_exchange : Alice demande la pubkey de Bob
        _tx_raw(ca, {"type": "get_pubkey", "target": "DM_Bob"})
        time.sleep(0.3)
        alice_msgs = drain(ca, 1.0)
        pubkey_resp = [m for m in alice_msgs if m.get("type") == "pubkey_response"]
        T("Serveur répond à get_pubkey avec la clé publique", len(pubkey_resp) > 0)

        if pubkey_resp:
            # Encoder un DM avec la clé de session de test (en pratique le client
            # utilise la pubkey RSA du destinataire, ici on vérifie juste le relayage)
            dm_ct = tea_cipher.encrypt_b64("dm_test_content", key_a)
            sig_dm = kem_mod.rsa_sign(dm_ct.encode(), TEST_PRIV)
            sig_b64 = base64.b64encode(sig_dm).decode()
            _tx_raw(ca, {"type": "dm", "to": "DM_Bob", "content": dm_ct,
                         "signature": sig_b64})
            time.sleep(0.3)
            bob_dms = [m for m in drain(cb, 1.0) if m.get("type") == "dm"]
            T("Bob reçoit le DM (type='dm')",            len(bob_dms) > 0)
            if bob_dms:
                dm = bob_dms[0]
                T("DM contient 'from': Alice",           dm.get("from") == "DM_Alice")
                T("DM contient 'content' (chiffré)",     dm.get("content") is not None)
                T("DM contient 'signature'",             dm.get("signature") is not None)
                # Le plaintext ne doit pas apparaître en clair
                raw_b = json.dumps(dm).encode()
                T("Plaintext ABSENT du DM (chiffré)",    b"dm_test_content" not in raw_b)

    quit_client(ca)
    quit_client(cb)
    for u in ["DM_Alice", "DM_Bob"]:
        server_instance.delete_user(u, notify=False)


# ═══════════════════════════════════════════════════════════════════
#  SÉCURITÉ — Observations et vérifications
# ═══════════════════════════════════════════════════════════════════

def test_security():
    section("SÉCURITÉ — Vérifications & observations")

    src = open("server.py").read()

    doing("Aucun mot de passe en clair dans this_is_safe.txt")
    safe = open("this_is_safe.txt").read()
    T("Aucun mot de passe en clair dans this_is_safe.txt", "StrongP4ss" not in safe)

    doing("Comparaison en temps constant")
    T("hmac.compare_digest utilisé (résistance timing attacks)",
      "hmac.compare_digest" in src)

    doing("Signatures RSA disponibles (Partie 3)")
    T("rsa_sign implémenté dans kem.py",   "def rsa_sign"   in open("kem.py").read())
    T("rsa_verify implémenté dans kem.py", "def rsa_verify" in open("kem.py").read())

    doing("Vérification des signatures via round-trip")
    msg = b"Message a signer"
    sig = kem_mod.rsa_sign(msg, TEST_PRIV)
    T("rsa_sign → rsa_verify → OK",            kem_mod.rsa_verify(msg, sig, TEST_PUB))
    T("Signature invalide sur message modifié",
      not kem_mod.rsa_verify(b"Message different", sig, TEST_PUB))

    doing("Clés de chiffrement absentes des logs serveur")
    log_files = glob.glob("log_*.txt")
    if log_files:
        log = open(log_files[-1]).read()
        # Vérifie qu'aucune clé de session (hex 32 chars) ou affectation key= ne traîne dans les logs
        import re as _re
        has_hex_key = bool(_re.search(r'\b[0-9a-f]{32}\b', log.lower()))
        has_key_assign = "session_key=" in log.lower() or "key=b'" in log.lower()
        T("Clés absentes des logs", not has_hex_key and not has_key_assign)

    doing("Observations de sécurité (non-bloquantes)")
    # Vérifier si _verify_password retourne tôt pour user inconnu
    verify_src = ""
    in_v = False
    for line in src.split("\n"):
        if "def _verify_password" in line: in_v = True
        elif in_v and line.strip().startswith("def "): break
        if in_v: verify_src += line + "\n"
    if ("return False" in verify_src and "compare_digest" in verify_src and
            verify_src.index("return False") < verify_src.index("compare_digest")):
        W("_verify_password retourne tôt si user inconnu → timing leak (énumération usernames)")
    W("Commandes /create et /join envoient les mdp de room en CLAIR sur TCP")
    W("Le serveur log les messages déchiffrés (comportement normal pour serveur centralisé)")
    if "import string" in src:
        I("'import string' présent dans server.py mais inutilisé (nettoyage cosmétique)")


# ═══════════════════════════════════════════════════════════════════
#  RÉSUMÉ FINAL
# ═══════════════════════════════════════════════════════════════════

def summary():
    total = _passed + _failed
    pct   = (_passed / total * 100) if total else 0
    bar_w = 44
    filled = int(bar_w * _passed / total) if total else 0

    bar = f"{GRN}{'█' * filled}{RED}{'░' * (bar_w - filled)}{RST}"
    print(f"\n{BOLD}{BLU}╔{'═'*58}╗{RST}")
    print(f"{BOLD}{BLU}║{'RÉSUMÉ FINAL'.center(58)}║{RST}")
    print(f"{BOLD}{BLU}╠{'═'*58}╣{RST}")
    print(f"{BOLD}{BLU}║  {bar}  ║{RST}")
    print(f"{BOLD}{BLU}║  {GRN}✅ Passés  : {_passed:<5}{RST}{RED}❌ Échoués : {_failed:<5}{RST}   {BOLD}{BLU}║{RST}")
    print(f"{BOLD}{BLU}║  {BOLD}Total      : {total:<5}  Taux : {pct:.0f}%{RST}{'':15}{BOLD}{BLU}║{RST}")
    if _warnings:
        print(f"{BOLD}{BLU}╠{'═'*58}╣{RST}")
        print(f"{BOLD}{BLU}║  {YEL}⚠️  {len(_warnings)} observation(s) de sécurité{RST}{'':20}{BOLD}{BLU}║{RST}")
        for w in _warnings:
            short = (w[:52] + "…") if len(w) > 52 else w
            print(f"{BOLD}{BLU}║    {YEL}• {short:<54}{BOLD}{BLU}║{RST}")
    print(f"{BOLD}{BLU}╚{'═'*58}╝{RST}\n")


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def cleanup():
    for f in glob.glob("log_*.txt"):
        try: os.remove(f)
        except Exception: pass
    for f in ["this_is_safe.txt", "user_keys_do_not_steal_plz.txt"]:
        try: os.remove(f)
        except Exception: pass
    shutil.rmtree("users", ignore_errors=True)


def main():
    global TEST_PUB, TEST_PRIV

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    banner()

    print(f"  {DIM}Nettoyage des artefacts précédents...{RST}")
    cleanup()

    print(f"\n  {MAG}▶  Génération de la paire RSA-1024 pour les tests (peut prendre 1–2 s)...{RST}",
          end="", flush=True)
    TEST_PUB, TEST_PRIV = kem_mod.generate_keypair()
    print(f" {GRN}OK{RST}")

    print(f"  {MAG}▶  Démarrage du serveur sur le port {PORT}...{RST}", end="", flush=True)
    start_server()
    print(f" {GRN}OK{RST}\n")

    try:
        test_jour1()
        test_jour2()
        test_jour3()
        test_dm_and_protected()
        test_security()
    except KeyboardInterrupt:
        print(f"\n\n  {YEL}Interrompu par l'utilisateur.{RST}\n")
    except Exception as e:
        print(f"\n  {RED}💥 EXCEPTION : {e}{RST}")
        import traceback
        traceback.print_exc()
    finally:
        summary()
        print(f"  {DIM}Nettoyage final...{RST}")
        cleanup()


if __name__ == "__main__":
    main()
