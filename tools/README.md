Tools for cracking and migrating passwords

Overview:
- md5_decrypted.txt : instructions and placeholder for the hacker message crack.
- run_hashcat.sh     : helper script to run hashcat against the hacker hash (if hashcat installed).
- crack_users.py     : Extract MD5 hashes from a sqlite users table, run hashcat (if available) to crack short passwords, and update DB (audit column).
- rehash_passwords.py: Migration script that re-hashes recovered plaintexts into secure algorithm format and stores username:algorithm:cost:salt_base64:digest.

Important notes:
- This repo environment may not have hashcat or GPU drivers. Run hashcat locally on your machine and then re-run the Python scripts to update DB/migrate.
- BACKUP your database before running any of these scripts.
- Dependencies (install via pip): bcrypt
  pip install bcrypt

Usage examples:
- Crack hacker message with hashcat (locally):
  bash tools/run_hashcat.sh
  # then edit md5_decrypted.txt to include the recovered plaintext

- Crack users (attempts to use hashcat if available; otherwise it will only dump candidate hashes):
  python3 tools/crack_users.py --db path/to/your.db --table users --hashcol password --use-hashcat

- Rehash recovered passwords into bcrypt format:
  python3 tools/rehash_passwords.py --db path/to/your.db --table users --usercol username --plaintextcol audit_plain
