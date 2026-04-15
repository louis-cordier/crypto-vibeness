# Crypto-Vibe — Résumé du projet

## 📋 Vue d'ensemble

Chat multi-utilisateurs de type IRC, développé en Python pur (sans framework),
avec une montée progressive en sécurité :

| Phase | Description |
|-------|-------------|
| **Jour 1 — Partie 1** | Chat basique multi-rooms, logs, couleurs |
| **Jour 1 — Partie 2** | Authentification MD5 + sel, règles de mot de passe |
| **Jour 2 — Partie 1** | Chiffrement symétrique TEA-CBC sur tous les messages |
| **Jour 2 — Partie 2** | Chiffrement hybride RSA-KEM (échange de clé asymétrique) |
| **Jour 2 — Partie 3** | E2EE pour les DMs + signatures numériques RSA |

---

## 📁 Fichiers du projet

| Fichier | Rôle |
|---------|------|
| `server.py` | Serveur de chat (~680 lignes) |
| `client.py` | Client de chat (~420 lignes) |
| `tea_cipher.py` | Chiffrement TEA en mode CBC + PBKDF2 (~150 lignes) |
| `kem.py` | RSA-1024 KEM + signatures numériques (~270 lignes) |
| `password_rules.json` | Règles de validation des mots de passe (modifiables) |
| `this_is_safe.txt` | Table de mots de passe hashés (créé automatiquement) |
| `test_audit.py` | Suite de 67 tests automatisés |
| `PLAN_DE_TEST.md` | Plan de test détaillé |

---

## ⚙️ Fonctionnalités implémentées

### Chat de base
- Serveur multi-clients avec `threading`
- Système de **rooms** (salons) avec room `general` par défaut
- Rooms protégées par **mot de passe** (affichées avec 🔒 dans la liste)
- **Unicité des pseudos** — un username ne peut être connecté qu'une fois
- **Couleur déterministe** par utilisateur (basée sur le username, via ANSI)
- **Timestamps** sur tous les messages `[HH:MM:SS]`
- **Logs serveur** dans un fichier horodaté `log_YYYY-MM-DD_HH-MM-SS.txt`

### Authentification
- Authentification obligatoire avant l'accès au chat
- Création de compte à la première connexion (mot de passe + confirmation)
- **3 règles de mot de passe** configurables dans `password_rules.json` :
  - Minimum 8 caractères
  - Au moins une majuscule
  - Au moins un chiffre
- Indicateur de **force du mot de passe** (entropie Shannon : faible/moyen/fort/très fort)
- Mots de passe hashés en **MD5 + sel aléatoire** (96 bits / 12 octets)
- Stockage : `username:salt_b64:hash_b64` dans `this_is_safe.txt`
- Vérification en **temps constant** (`hmac.compare_digest`)
- Suppression de compte avec `/deleteaccount`

### Chiffrement symétrique (TEA-CBC)
- **TEA** (Tiny Encryption Algorithm) : blocs de 64 bits, clé de 128 bits, 32 rounds Feistel
- Mode **CBC** avec IV aléatoire de 8 octets (préfixé au chiffré)
- Padding **PKCS#7**
- Dérivation de clé via **PBKDF2** (SHA-256, 100 000 itérations)

### Chiffrement hybride (RSA-KEM)
- **RSA-1024** : génération de clés (p, q premiers, e = 65537)
- Padding **PKCS#1 v1.5** pour l'encapsulation
- **Handshake KEM** à la connexion :
  1. Le client génère une paire RSA et envoie sa clé publique
  2. Le serveur génère une clé de session aléatoire (128 bits)
  3. Le serveur chiffre cette clé avec la clé publique du client (RSA)
  4. Le client déchiffre → les deux partagent la clé de session
- Tous les messages sont chiffrés avec TEA-CBC en utilisant cette clé de session
- Clés RSA persistées localement : `users/<username>/public.key` et `private.key`
- Plus de clés stockées côté serveur (clés de session éphémères en mémoire)

### E2EE et signatures numériques
- **Annuaire de clés publiques** sur le serveur `{username: {n, e}}`
- **Messages directs (DMs) chiffrés de bout en bout** :
  1. L'expéditeur demande la clé publique du destinataire au serveur
  2. Génère une clé de session DM aléatoire (128 bits)
  3. Chiffre cette clé avec la clé publique RSA du destinataire
  4. Échange la clé via le serveur (opaque pour le serveur)
  5. Les messages sont chiffrés en TEA-CBC avec cette clé peer-to-peer
  6. Le serveur ne peut **jamais** déchiffrer les DMs
- **Signatures numériques RSA** sur tous les messages :
  - Padding PKCS#1 v1.5 type 1 + SHA-256
  - Messages de room : signature du texte en clair
  - DMs : signature du texte chiffré
  - Vérification obligatoire côté destinataire
  - **Alerte de sécurité** `⚠️ SECURITY ALERT` si signature invalide ou message altéré

---

## 🖥️ Commandes de lancement

### Démarrer le serveur

```bash
# Avec port personnalisé
python3 server.py 5555

# Port par défaut (5050)
python3 server.py
```

### Démarrer un client

```bash
# Se connecter au serveur
python3 client.py <adresse_ip> <port>

# Exemples
python3 client.py 127.0.0.1 5555        # localhost
python3 client.py 192.168.1.42 5555      # autre machine sur le réseau
```

---

## 💬 Commandes du chat

| Commande | Description |
|----------|-------------|
| `/help` | Affiche la liste des commandes disponibles |
| `/rooms` | Liste tous les salons (🔒 = protégé par mot de passe) |
| `/create <nom> [mdp]` | Crée un salon (optionnellement protégé) |
| `/join <nom> [mdp]` | Rejoint un salon existant |
| `/leave` | Retourne dans le salon `general` |
| `/who` | Liste les utilisateurs du salon actuel |
| `/dm <utilisateur> <message>` | Envoie un message privé chiffré E2EE |
| `/deleteaccount` | Supprime son propre compte (demande confirmation) |
| `/quit` | Se déconnecter |

---

## 🧪 Comment tester

### Test rapide en local

Ouvrir **3 terminaux** dans le dossier `e2e-chat/` :

**Terminal 1 — Serveur :**
```bash
python3 server.py 5555
```

**Terminal 2 — Client Alice :**
```bash
python3 client.py 127.0.0.1 5555
# Entrer le pseudo : Alice
# Créer un mot de passe : MonPass1! (respecter les règles)
```

**Terminal 3 — Client Bob :**
```bash
python3 client.py 127.0.0.1 5555
# Entrer le pseudo : Bob
# Créer un mot de passe : MonPass2!
```

### Scénarios de test

#### 1. Messages de room
```
Alice> Bonjour tout le monde !    ← Bob voit le message avec timestamp et couleur
Bob>   Salut Alice !               ← Alice voit le message
```

#### 2. Rooms et mots de passe
```
Alice> /create secret monmdp       ← Crée un salon protégé
Alice> /rooms                      ← Le salon "secret" apparaît avec 🔒
Alice> /join secret monmdp         ← Alice rejoint
Bob>   /join secret                ← ❌ Mot de passe incorrect
Bob>   /join secret monmdp         ← ✅ Bob rejoint
```

#### 3. Message privé E2EE
```
Alice> /dm Bob Ceci est un message secret
       ← Bob reçoit : "[DM] Alice: Ceci est un message secret"
       ← Le serveur ne voit qu'un blob chiffré dans ses logs
```

#### 4. Unicité des pseudos
```
# Si Alice est déjà connectée, un autre client essayant "Alice" sera refusé
```

#### 5. Suppression de compte
```
Alice> /deleteaccount
       ← Le serveur demande le mot de passe
       ← Si correct : compte supprimé, déconnexion
```

### Suite de tests automatisée

```bash
python3 test_audit.py
```

Cette suite exécute **67 tests** couvrant :
- Import des modules (server, client, tea_cipher, kem)
- Chiffrement/déchiffrement TEA-CBC
- Génération RSA et KEM
- Hachage et vérification des mots de passe
- Règles de mot de passe
- Signatures numériques
- Format du fichier `this_is_safe.txt`
- Logs serveur

### Vérifier le chiffrement du trafic

```bash
# Capturer le trafic réseau pour vérifier que les messages sont chiffrés
sudo tcpdump -i lo -A port 5555 | grep -i "bonjour"
# → Aucun texte en clair ne doit apparaître
```

---

## 🔐 Architecture de sécurité

```
┌─────────┐         RSA-KEM          ┌──────────┐         RSA-KEM          ┌─────────┐
│  Alice   │◄──────────────────────► │  Serveur  │◄──────────────────────► │   Bob   │
│          │   clé session serveur    │           │   clé session serveur    │         │
│          │                          │           │                          │         │
│          │     E2EE (DM direct)     │  (relay   │     E2EE (DM direct)     │         │
│          │◄─────────────────────────┤  opaque)  ├─────────────────────────►│         │
│          │   clé session peer       │           │   clé session peer       │         │
└─────────┘                          └──────────┘                          └─────────┘

Messages room : Alice → [TEA-CBC + clé serveur] → Serveur → [TEA-CBC + clé serveur] → Bob
Messages DM   : Alice → [TEA-CBC + clé peer]   → Serveur (opaque) → Bob → [déchiffre]
Signatures    : Tous les messages signés RSA (SHA-256 + PKCS#1 v1.5)
```

---

## 📝 Fichiers générés automatiquement

| Fichier | Contenu |
|---------|---------|
| `this_is_safe.txt` | `username:salt_b64:hash_b64` (un utilisateur par ligne) |
| `log_YYYY-MM-DD_HH-MM-SS.txt` | Logs horodatés des événements serveur |
| `users/<username>/public.key` | Clé publique RSA (n, e) en JSON |
| `users/<username>/private.key` | Clé privée RSA (n, d) en JSON |
| `password_rules.json` | Règles de mot de passe (modifiable) |
