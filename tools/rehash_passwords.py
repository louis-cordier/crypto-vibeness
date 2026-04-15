#!/usr/bin/env python3
"""Re-hash recovered plaintext passwords into secure salted format.
Format stored in password column:
  username:algorithm:cost_factor:salt_base64:digest

This script:
 - detects sqlite DB (or use --db)
 - reads each user with plaintext in plaintextcol
 - generates 96-bit salt (12 bytes), base64-encodes it
 - computes bcrypt hash of salt||password using bcrypt with given cost
 - stores formatted string into pwdcol

WARNING: BACKUP your database before running.
"""
import argparse
import sqlite3
import os
import base64
import secrets

try:
    import bcrypt
except Exception:
    raise SystemExit('Please install bcrypt: pip install bcrypt')


def find_db_default():
    for fn in ['users.db', 'db.sqlite3', 'database.db', 'app.db']:
        if os.path.exists(fn):
            return fn
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', help='Path to sqlite DB (default: auto-detect)')
    p.add_argument('--table', default='users')
    p.add_argument('--usercol', default='username')
    p.add_argument('--plaintextcol', default='audit_plain')
    p.add_argument('--pwdcol', default='password')
    p.add_argument('--algo', default='bcrypt', choices=['bcrypt'], help='Hash algorithm')
    p.add_argument('--cost', type=int, default=12, help='Cost factor (bcrypt rounds)')
    args = p.parse_args()

    dbpath = args.db or find_db_default()
    if not dbpath or not os.path.exists(dbpath):
        print('DB not found; provide --db or create a DB file')
        return

    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()

    # Ensure plaintext column exists
    try:
        cur.execute(f"ALTER TABLE {args.table} ADD COLUMN {args.plaintextcol} TEXT")
        conn.commit()
    except Exception:
        pass

    # Read users
    cur.execute(f"SELECT rowid, {args.usercol}, {args.plaintextcol}, {args.pwdcol} FROM {args.table}")
    rows = cur.fetchall()
    updated = 0
    for rid, username, plain, oldpwd in rows:
        if not plain:
            continue
        # Skip if password already in new format (heuristic: contains 4 colons)
        if oldpwd and isinstance(oldpwd, str) and oldpwd.count(':') >= 4:
            print(f'Skipping {username}: already in new format')
            continue
        # generate 12 bytes = 96 bits salt
        salt = secrets.token_bytes(12)
        salt_b64 = base64.b64encode(salt).decode('ascii')
        # compute bcrypt on ASCII-safe input: salt_b64 + plaintext (avoids NUL bytes)
        to_hash = (salt_b64 + plain).encode('utf-8')
        hashed = bcrypt.hashpw(to_hash, bcrypt.gensalt(rounds=args.cost))
        digest = hashed.decode('utf-8')
        formatted = f"{username}:{args.algo}:{args.cost}:{salt_b64}:{digest}"
        cur.execute(f"UPDATE {args.table} SET {args.pwdcol} = ? WHERE rowid = ?", (formatted, rid))
        updated += 1
    conn.commit()
    conn.close()
    print(f'Rehashed and updated {updated} users into {args.pwdcol} with algorithm {args.algo} (cost {args.cost})')

if __name__ == '__main__':
    main()