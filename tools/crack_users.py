#!/usr/bin/env python3
"""Extract MD5 hashes from a sqlite users table and prepare for cracking.
This script will:
 - detect a sqlite DB (path provided by --db)
 - extract distinct MD5 hash values from the specified table/column
 - write them to hashes_to_crack.txt
 - optionally call hashcat (if available) to attempt brute-force for passwords <= length 5
 - update the database by adding an audit column (audit_plain) and storing recovered plaintexts

USAGE:
  python3 tools/crack_users.py --db ./users.db --table users --hashcol password --use-hashcat

WARNING: Back up your DB before running.
"""

import argparse
import sqlite3
import os
import subprocess
from shutil import which


def find_db_default():
    # Common filenames
    for fn in ['users.db', 'db.sqlite3', 'database.db', 'app.db']:
        if os.path.exists(fn):
            return fn
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', help='Path to sqlite DB (default: auto-detect)')
    p.add_argument('--table', default='users')
    p.add_argument('--hashcol', default='password')
    p.add_argument('--plaintextcol', default='audit_plain')
    p.add_argument('--use-hashcat', action='store_true', help='Invoke hashcat if present')
    args = p.parse_args()

    dbpath = args.db or find_db_default()
    if not dbpath:
        print('No database found. Provide --db')
        return
    if not os.path.exists(dbpath):
        print('DB not found at', dbpath)
        return

    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()

    # ensure plaintext audit column exists
    try:
        cur.execute(f"ALTER TABLE {args.table} ADD COLUMN {args.plaintextcol} TEXT")
        conn.commit()
        print('Added column', args.plaintextcol)
    except Exception:
        # ignore if exists
        pass

    # collect candidate hashes (assumed to be MD5 hex 32 chars)
    cur.execute(f"SELECT rowid, {args.hashcol} FROM {args.table}")
    rows = cur.fetchall()
    hashes = []
    rows_map = {}
    for rid, h in rows:
        if h and isinstance(h, str) and len(h)==32:
            hashes.append(h)
            rows_map.setdefault(h, []).append(rid)
    if not hashes:
        print('No MD5-like hashes found in', args.table)
        return

    uniq_hashes = sorted(set(hashes))
    with open('hashes_to_crack.txt','w') as f:
        for h in uniq_hashes:
            f.write(h+'\n')
    print('Wrote', len(uniq_hashes), 'unique hashes to hashes_to_crack.txt')

    # Optionally call hashcat for length<=5 passwords (brute-force)
    if args.use_hashcat and which('hashcat'):
        # run hashcat with mask up to 5 chars: try lengths 1..5 using ?a (example only)
        # WARNING: brute-forcing the full ?a space is expensive; prefer wordlists or targeted masks.
        cmd = ['hashcat','-m','0','-a','3','hashes_to_crack.txt','?a?a?a?a?a','--outfile-format=2','--outfile=cracked_users.txt']
        print('Running hashcat:', ' '.join(cmd))
        subprocess.run(cmd)
        print('Hashcat finished, see cracked_users.txt')
    else:
        print('Hashcat not used or not available. You can run locally:')
        print('  hashcat -m 0 -a 3 hashes_to_crack.txt ?a ?a?a ?a?a?a ?a?a?a?a ?a?a?a?a?a --outfile=cracked_users.txt --outfile-format=2')

    # If cracked_users.txt exists, parse and update DB
    if os.path.exists('cracked_users.txt'):
        print('Parsing cracked_users.txt and updating DB audit column')
        with open('cracked_users.txt') as f:
            for line in f:
                line=line.strip()
                if not line or ':' not in line:
                    continue
                h,p = line.split(':',1)
                if h in rows_map:
                    for rid in rows_map[h]:
                        cur.execute(f"UPDATE {args.table} SET {args.plaintextcol} = ? WHERE rowid = ?", (p, rid))
        conn.commit()
        print('Database updated with recovered plaintexts (in column', args.plaintextcol,')')
    else:
        print('No cracked_users.txt found; skipping DB update')

    conn.close()

if __name__ == '__main__':
    main()
