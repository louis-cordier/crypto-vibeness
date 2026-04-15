# Verification checklist — Crypto Vibeness (Day 01 → Migration + Encryption)

Ce fichier rassemble toutes les commandes et vérifications pour reproduire et valider les étapes du projet : craquage MD5, mise à jour DB, migration vers bcrypt avec sel unique, et chiffrement symétrique des messages.

---
Prerequisites
- Linux machine with: python3, pip, sqlite3 (client), hashcat (recommended for cracking)
- Python deps: bcrypt, pycryptodome or cryptography
  - Install: `pip install bcrypt pycryptodome` (or `pip install cryptography`)

Fichiers importants
- server.py, client.py : chat (server unchanged)
- client_secure.py : client that encrypts outgoing messages and attempts decryption on incoming messages
- crypto_utils.py : derive_key (PBKDF2-HMAC-SHA256), encrypt_message/decrypt_message (AES-CBC + PKCS7)
- tools/
  - derive_user_key.py : prompt passphrase, derive key, write server key file and client key file
  - user_keys_do_not_steal_plz.txt : server-side key store (appended by derive_user_key)
  - run_hashcat.sh / run_crack_users_hashcat.sh / crack_users.py / rehash_passwords.py : crack + migrate pipeline
- md5_decrypted.txt : placeholder / résultat du crack du message hacker

---
Étapes et commandes (expliquées)

0) Sauvegarde (obligatoire)
- Copier la DB avant toute opération :
  `cp path/to/your.db path/to/your.db.bak`

1) Craquer le message du hacker (hash : `35b95f7c0f63631c453220fb2a86f218`)
- Méthode recommandée (local, GPU/CPU) :
  ```bash
  echo "35b95f7c0f63631c453220fb2a86f218" > target_hash.txt
  hashcat -m 0 -a 3 target_hash.txt ?u?u?l?l?u?u?s --status --status-timer=10 \
    --outfile=md5_decrypted.txt --outfile-format=2
  ```
- Alternative helper (script fourni) : `bash tools/run_hashcat.sh`

2) Gestion des clés symétriques (création et stockage)
- Pour créer/derive la clé d'un utilisateur (server + client file):
  ```bash
  python3 tools/derive_user_key.py <username>
  # enter passphrase interactively (or pass --passphrase '...')
  ```
  - Ceci écrit (server) `user_keys_do_not_steal_plz.txt` line: `username:pbkdf2:100000:salt_base64:key_base64`
  - Et crée (client) `./users/<username>/key.txt` contenant the base64 key (raw)
- Détails : PBKDF2-HMAC-SHA256 used, iterations default 100000, key length default 16 bytes (128 bits), salt = 12 bytes (96 bits) base64 encoded.

3) Chiffrer/Déchiffrer messages (usage client)
- Start server normally.
- Start secure client:
  ```bash
  python3 client_secure.py --host 127.0.0.1 --port 12345
  ```
- On connect, provide your username. Ensure `./users/<username>/key.txt` exists (see step 2).
- Sending messages: client_secure encrypts outgoing messages with AES-CBC (IV random 16 bytes) and sends base64(iv + ciphertext).
- Receiving messages: client attempts to find `./users/<sender>/key.txt` (base64) and will call `decrypt_message` to recover plaintext. If sender key not present, client displays raw message blob.

4) Helper functions (in crypto_utils.py)
- derive_key(passphrase, salt=None, iterations=100000, key_len=16) -> (salt_b64, key_bytes)
- encrypt_message(key_bytes, plaintext) -> base64(iv + ciphertext)
- decrypt_message(key_bytes, b64_iv_ciphertext) -> plaintext string

5) Pipeline MD5 crack → migrate (résumé)
- Extract hashes: `python3 tools/crack_users.py --db path/to/your.db --table users --hashcol password`
- Crack with hashcat (local): `bash tools/run_crack_users_hashcat.sh`
- Parse results: re-run crack_users.py to populate `audit_plain` from `cracked_users.txt`
- Re-hash to bcrypt format: `python3 tools/rehash_passwords.py --db path/to/your.db --table users --usercol username --plaintextcol audit_plain --pwdcol password --cost 12`

6) Vérifications pour le chiffrement
- Check server key store:
  ```bash
  sed -n '1,200p' user_keys_do_not_steal_plz.txt
  # lines: username:pbkdf2:iterations:salt_base64:key_base64
  ```
- Check client key exists:
  ```bash
  cat ./users/<username>/key.txt
  # should be base64 key
  ```
- Verify derivation consistency (python):
  ```python
  from crypto_utils import derive_key
  salt_b64, key = derive_key('passphrase')  # new random salt
  # To verify stored entry: base64.b64decode(stored_key_b64) == key_bytes
  ```
- Encrypt/decrypt round-trip test (python):
  ```python
  from crypto_utils import derive_key, encrypt_message, decrypt_message
  s,k = derive_key('pw', None, iterations=100000, key_len=16)
  ct = encrypt_message(k, 'hello')
  assert decrypt_message(k, ct) == 'hello'
  ```

7) Sécurité & limites (importants)
- Current design stores server-side keys in cleartext file `user_keys_do_not_steal_plz.txt` — this is INSECURE for production. Keep for testing only.
- Message decryption on receiver requires access to sender's key file. In this implementation clients must have other users' keys available locally to decrypt. Alternatives:
  - Use pairwise shared keys or a secure key-exchange (e.g., Diffie-Hellman) per pair/room.
  - Use public-key crypto (e.g., RSA/EC) so sender encrypts to recipient's public key.
- IV is prepended to ciphertext and base64 encoded; AES-CBC is used with PKCS7 padding.

8) Tests locaux (encryption)
- Create two users and keys:
  ```bash
  python3 tools/derive_user_key.py alice
  python3 tools/derive_user_key.py bob
  ```
- Start server, start two clients (client_secure.py) in separate terminals. To let each decrypt the other's messages for testing, copy `./users/alice/key.txt` to the other machine's `./users/alice/key.txt` and vice versa (or run both clients on same machine).
- Send messages: they should appear decrypted if corresponding sender key present locally.

---
Dépannage / notes
- Install `pycryptodome` or `cryptography` to enable AES backends: `pip install pycryptodome` or `pip install cryptography`.
- If decrypt fails, ensure the correct sender key file exists and is the exact key derived from the passphrase.
- For production, do NOT store keys in cleartext on server; implement secure key exchange or public-key scheme.

---
Résumé des attentes (checklist)
- [x] Key derivation PBKDF2-HMAC-SHA256, 128-bit key, 96-bit salt (base64) — implemented
- [x] Server key storage `user_keys_do_not_steal_plz.txt` — implemented
- [x] Client key storage `./users/<username>/key.txt` — implemented
- [x] AES-CBC encryption with IV prepended (base64) — implemented
- [x] Integration in client (client_secure.py) — implemented
- [~] Decryption model: implemented via local presence of sender key; if you intended receiver to use own key, change design (note above)

---
Besoin d'une checklist automatisée (script) ? Je peux créer un outil `tools/verify_all.sh` qui exécute les contrôles non-destructifs et affiche les vérifications. Demande si tu veux que je le crée.
