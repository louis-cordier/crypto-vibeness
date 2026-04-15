#!/usr/bin/env bash
# Helper to run hashcat for the hacker message
set -euo pipefail
HASH=35b95f7c0f63631c453220fb2a86f218
OUT=md5_decrypted.txt
TMP=target_hash.txt

echo "$HASH" > "$TMP"
if ! command -v hashcat >/dev/null 2>&1; then
  echo "hashcat not found. Install hashcat and re-run this script."
  exit 1
fi
# Mask: ?u?u?l?l?u?u?s
hashcat -m 0 -a 3 "$TMP" ?u?u?l?l?u?u?s --status --status-timer=10 --outfile="$OUT" --outfile-format=2
echo "Done. Results (if any) written to $OUT"