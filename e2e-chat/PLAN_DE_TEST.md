# Plan de Test — Crypto-Vibe Chat

## 1. Résumé de conformité

| Exigence | Statut | Détail |
|----------|--------|--------|
| Serveur multi-client, port configurable | ✅ | `DEFAULT_PORT = 5555`, `sys.argv[1]` |
| Unicité des pseudos | ✅ | Erreur si username déjà connecté |
| Rooms + room par défaut `general` | ✅ | `/create`, `/join`, `/leave` |
| Rooms protégées par mot de passe | ✅ | 🔒 dans `/rooms`, refus sans bon mdp |
| Isolation des messages par room | ✅ | Seuls les membres voient les messages |
| Timestamps HH:MM:SS | ✅ | Champ `timestamp` dans chaque message |
| Couleur déterministe (MD5 du username) | ✅ | Même couleur partout, toute la session |
| Logs serveur `log_YYYY-MM-DD_HH-MM-SS.txt` | ✅ | Connexions, messages, déconnexions |
| Auth MD5 + base64 | ✅ | `hashlib.md5`, `base64.b64encode` |
| Sel ≥ 96 bits par utilisateur | ✅ | 16 octets (128 bits) |
| `this_is_safe.txt` format `user:salt:hash` | ✅ | Pas de mdp en clair |
| 3 règles de mdp dans `password_rules.json` | ✅ | min_length, uppercase, digit |
| Indicateur force (entropie Shannon) | ✅ | 5 niveaux, bits affichés |
| Vérification temps constant | ✅ | `hmac.compare_digest` |
| Non-auth ne reçoit pas les messages | ✅ | Phase auth bloquante |
| TEA-CBC, blocs 64 bits, clé 128 bits | ✅ | `tea_cipher.py` |
| KDF PBKDF2-HMAC-SHA256, 100k itérations | ✅ | Sel 16 octets par utilisateur |
| `user_keys_do_not_steal_plz.txt` | ✅ | Format `user:salt_b64:key_b64` |
| Client stocke clé dans `./users/<user>/key.txt` | ✅ | |
| Chiffrement par bloc sur le réseau | ✅ | Plaintext absent du flux TCP |

### Observations de sécurité (⚠️ non-bloquantes)

| Observation | Risque | Note |
|-------------|--------|------|
| `_verify_password` retourne tôt si user inconnu | Timing leak → énumération d'usernames | Faire un hash factice avant de retourner `False` |
| Mots de passe de room en clair en mémoire | Comparaison non-constante (`!=`) | Hors scope du sujet |
| Commandes `/create` `/join` non chiffrées | Mdp de room transitent en clair sur TCP | Le sujet ne l'exige pas |
| Logs serveur contiennent le plaintext | Normal pour serveur centralisé | À noter en audit |
| `import string` inutilisé | Aucun risque | Nettoyage cosmétique |

---

## 2. Tests manuels — Commandes CLI

### 2.1 Lancement serveur

```bash
# Port par défaut (5555)
cd e2e-chat && python3 server.py

# Port personnalisé
python3 server.py 9999
```
**Résultat attendu** : `Server listening on port 5555` (ou `9999`)

### 2.2 Connexion client

```bash
# Même machine
python3 client.py

# Depuis un autre PC (même réseau)
python3 client.py 192.168.1.X 5555
```
**Résultat attendu** : Prompt `Choose a username:`

### 2.3 Création de compte

```
Choose a username: Alice
[Nouveau] Entrez un mot de passe:
Confirmez le mot de passe:
Entrez un secret de chiffrement:
```
**Résultat attendu** :
- Affichage des règles de mot de passe
- Si mdp faible → `❌ Password rejected` + règles violées
- Si mdp OK → `Password strength: 🟢 Fort (XX.X bits)` + prompt secret + `Welcome Alice!`

### 2.4 Login existant

```
Choose a username: Alice
Enter your password: ********
```
**Résultat attendu** : `Welcome back Alice!`

### 2.5 Mauvais mot de passe

```
Choose a username: Alice
Enter your password: wrongpwd
```
**Résultat attendu** : `Wrong password.` + déconnexion

### 2.6 Unicité des pseudos

Ouvrir 2 clients, entrer le même username.

**Résultat attendu** : `Username 'Alice' is already connected.`

### 2.7 Commandes de room

```
/rooms                          # Lister les rooms
/create salon_prive             # Créer une room ouverte
/create salon_secret mdp123     # Créer une room protégée
/join salon_prive               # Rejoindre une room ouverte
/join salon_secret mdp123       # Rejoindre avec mot de passe
/join salon_secret              # Sans mot de passe → refusé
/join salon_secret mauvais      # Mauvais mot de passe → refusé
/who                            # Utilisateurs dans la room
/leave                          # Retour à general
```

**Résultats attendus** :
- `/rooms` → liste avec 🔒 pour rooms protégées
- `/join` sans/mauvais mdp → `Wrong or missing password`
- `/who` → `Users in 'salon_prive': Alice`
- `/leave` → retour à `general`

### 2.8 Isolation des messages

1. Client A dans `general`, Client B dans `salon_prive`
2. A envoie un message
3. B ne doit **PAS** voir le message de A

### 2.9 Suppression de compte

```
/deleteaccount
Confirm your password to delete your account: ********
```
**Résultat attendu** : `Your account has been deleted.` + déconnexion

**Vérification** :
```bash
cat this_is_safe.txt   # Le username ne doit plus y figurer
```

### 2.10 Déconnexion

```
/quit
```
**Résultat attendu** : Déconnexion propre, log serveur `X disconnected`

---

## 3. Vérification des fichiers de données

### 3.1 this_is_safe.txt

```bash
cat e2e-chat/this_is_safe.txt
```
**Format attendu** : `username:salt_en_base64:hash_en_base64` (une ligne par utilisateur)

**Vérifications** :
```bash
# Vérifier que le hash est du MD5 en base64 (16 octets = 24 chars b64)
awk -F: '{print length($3)}' this_is_safe.txt
# Chaque valeur doit être 24

# Vérifier que le sel fait 16 octets (24 chars b64)
awk -F: '{print length($2)}' this_is_safe.txt
# Chaque valeur doit être 24

# Vérifier que 2 users avec le même mdp ont des hashs différents
grep "Alice" this_is_safe.txt
grep "Bob" this_is_safe.txt
# Les champs salt ET hash doivent différer
```

### 3.2 user_keys_do_not_steal_plz.txt

```bash
cat e2e-chat/user_keys_do_not_steal_plz.txt
```
**Format attendu** : `username:salt_b64:key_b64`

```bash
# Vérifier taille de la clé (16 octets = 128 bits → 24 chars b64)
awk -F: '{print length($3)}' user_keys_do_not_steal_plz.txt

# Vérifier taille du sel (16 octets → 24 chars b64)
awk -F: '{print length($2)}' user_keys_do_not_steal_plz.txt
```

### 3.3 password_rules.json

```bash
cat e2e-chat/password_rules.json | python3 -m json.tool
```
**Résultat attendu** : 3 règles (min_length, uppercase, digit)

### 3.4 Fichier de log

```bash
ls e2e-chat/log_*.txt
cat e2e-chat/log_2026-04-15_*.txt
```
**Contenu attendu** : Connexions, messages, déconnexions avec timestamps

---

## 4. Vérification du chiffrement réseau

### 4.1 Avec tcpdump

```bash
# Terminal 1 : Lancer le serveur
cd e2e-chat && python3 server.py 5555

# Terminal 2 : Capturer le trafic TCP sur le port 5555
sudo tcpdump -i lo -A -s 0 'tcp port 5555' | tee capture.txt

# Terminal 3 : Lancer un client et envoyer un message
python3 client.py localhost 5555
# S'authentifier, puis envoyer : "MESSAGE_SECRET_TEST"

# Terminal 2 : Vérifier
grep "MESSAGE_SECRET_TEST" capture.txt
```
**Résultat attendu** : `grep` ne trouve **rien** — le plaintext n'apparaît pas dans la capture.

On doit voir du base64 (ciphertext) dans la capture, pas du texte lisible.

### 4.2 Avec tshark (alternative)

```bash
# Capturer 50 paquets sur le port 5555
sudo tshark -i lo -f 'tcp port 5555' -T fields -e data -c 50 | xxd -r -p

# Vérifier qu'aucun message en clair n'apparaît
sudo tshark -i lo -f 'tcp port 5555' -Y 'tcp.payload' -T fields \
  -e tcp.payload -c 20 2>/dev/null | while read hex; do
    echo "$hex" | xxd -r -p
done | grep -c "MESSAGE_SECRET_TEST"
```
**Résultat attendu** : `0` occurrences

### 4.3 Avec Python (programmatique)

```python
# Voir test_audit.py — test T3.10
# Le test vérifie que raw_recv() ne contient pas le plaintext
# et que le champ "encrypted": true est présent
```

---

## 5. Hashcat — Commandes de cracking

### 5.1 Crack MD5 avec masque spécifique

```bash
# Hash : 35b95f7c0f63631c453220fb2a86f218
# Masque : ?u?u?l?l?u?u?s (2 maj, 2 min, 2 maj, 1 spécial)
hashcat -m 0 -a 3 35b95f7c0f63631c453220fb2a86f218 '?u?u?l?l?u?u?s'

# Sauvegarder le résultat
hashcat -m 0 -a 3 35b95f7c0f63631c453220fb2a86f218 '?u?u?l?l?u?u?s' \
  --show > md5_decrypted.txt 2>&1
```

### 5.2 Brute-force MD5 (1 à 5 caractères)

```bash
hashcat -m 0 -a 3 <hash> '?a?a?a?a?a' --increment --increment-min 1
```

### 5.3 Vérifier les hashs de this_is_safe.txt

```bash
# Extraire les hashs MD5 du fichier (ils sont en base64, convertir en hex)
python3 -c "
import base64
with open('this_is_safe.txt') as f:
    for line in f:
        parts = line.strip().split(':',2)
        if len(parts)==3:
            h = base64.b64decode(parts[2]).hex()
            print(f'{parts[0]}: {h}')
"
```

---

## 6. Script de test automatisé

```bash
cd e2e-chat && python3 test_audit.py
```

Le script `test_audit.py` valide automatiquement **67 tests** couvrant :

| Section | Tests |
|---------|-------|
| Jour 1 — Chat IRC | 24 tests (port, rooms, isolation, couleurs, logs, commandes) |
| Jour 2 — Authentification | 19 tests (fichiers, format, sel, règles, entropie, login, deleteaccount) |
| Jour 3 — Chiffrement | 20 tests (TEA, CBC, KDF, clés, chiffrement réseau, re-login) |
| Sécurité | 4 tests + 3 observations ⚠️ |

**Résultat attendu** : `TOTAL: 67 ✅ | 0 ❌`

---

## 7. Architecture des fichiers

```
e2e-chat/
├── server.py                          # Serveur principal
├── client.py                          # Client
├── tea_cipher.py                      # Module TEA-CBC + PBKDF2
├── password_rules.json                # Règles de mot de passe (3 règles)
├── hash_password.py                   # Script bcrypt standalone
├── test_audit.py                      # Suite de tests automatisés
├── this_is_safe.txt                   # Table de mots de passe (runtime)
├── user_keys_do_not_steal_plz.txt     # Clés de chiffrement (runtime)
├── log_YYYY-MM-DD_HH-MM-SS.txt       # Logs serveur (runtime)
└── users/<username>/key.txt           # Clé côté client (runtime)
```
