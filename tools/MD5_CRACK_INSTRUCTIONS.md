Instructions to crack the hacker message and user MD5 passwords

1) Hacker message:
 - Hash: 35b95f7c0f63631c453220fb2a86f218
 - Exact hashcat command (brute-force mask ?u?u?l?l?u?u?s):
   echo "35b95f7c0f63631c453220fb2a86f218" > target_hash.txt
   hashcat -m 0 -a 3 target_hash.txt ?u?u?l?l?u?u?s --status --status-timer=10 --outfile=md5_decrypted.txt --outfile-format=2
 - After running, md5_decrypted.txt will contain: hash:plaintext

2) User passwords (<=5 chars):
 - Generate hashes_to_crack.txt using:
     python3 tools/crack_users.py --db path/to/your.db --table users --hashcol password
 - Run the provided script to brute-force masks 1..5 (uses hashcat):
     bash tools/run_crack_users_hashcat.sh
 - Results will be in cracked_users.txt (format hash:plaintext)
 - Update DB audit column by re-running crack_users.py (it will parse cracked_users.txt and update audit_plain)

3) Migration to bcrypt:
 - Ensure bcrypt is installed: pip install bcrypt
 - Run migration:
     python3 tools/rehash_passwords.py --db path/to/your.db --table users --usercol username --plaintextcol audit_plain --pwdcol password --cost 12
 - This will store entries in the format: username:bcrypt:12:salt_base64:digest

Notes:
- Always backup your DB before attempting cracking or migration.
- Brute-forcing with ?a and lengths up to 5 may still be expensive but feasible for MD5 on small keyspace; tailor masks for better results.
